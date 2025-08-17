#!/usr/bin/env python3
import asyncio
import datetime
import json
import logging
import os
import sys
import time
import uuid
from aiohttp import ClientError
from aiohttp import web
from qrcode import QRCode

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    AriesAgent,
    arg_parser,
    create_agent_with_args,
)
from runners.support.agent import (  # noqa:E402
    CRED_FORMAT_INDY,
    CRED_FORMAT_JSON_LD,
    SIG_TYPE_BLS,
)
from runners.support.utils import (  # noqa:E402
    log_msg,
    log_status,
    prompt,
    prompt_loop,
)

CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))
DEMO_EXTRA_AGENT_ARGS = os.getenv("DEMO_EXTRA_AGENT_ARGS")

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class UniRegCAgent(AriesAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        endorser_role: str = None,
        revocation: bool = False,
        anoncreds_legacy_revocation: str = None,
        log_file: str = None,
        log_config: str = None,
        log_level: str = None,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="UniRegC",
            no_auto=no_auto,
            endorser_role=endorser_role,
            revocation=revocation,
            anoncreds_legacy_revocation=anoncreds_legacy_revocation,
            log_file=log_file,
            log_config=log_config,
            log_level=log_level,
            **kwargs,
        )
        self.connection_id = None  # Student/holder connection (for backward compatibility)
        self.holder_connection_id = None  # Explicitly track holder connection
        self._connection_ready = None
        self.admin_connection_id = None  # Admin connection for approvals
        self.cred_state = {}
        self.cred_attrs = {}
        self.pending_credentials = {}  
        self.approval_responses = {}  
        self.cred_def_id = None
        
        # Multi-holder support
        self.holder_connections = {}  # {connection_id: {label, connected_at, credentials_issued, status}}
        self.credential_exchanges = {}  # {cred_ex_id: connection_id}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()
    
    def add_message_handler(self, message_type, handler):
        """
        Register a handler for messages with the specified type.
        
        Args:
            message_type (str): The message type to listen for
            handler (callable): The async function to call when a message of this type arrives
        """
        # For our demo purposes, we don't need to actually implement this
        # since we're using a custom message checking task
        log_msg(f"Message handler registered for {message_type} (Note: Using custom message checking)")

    def add_holder_connection(self, connection_id, label=None):
        """Add a new holder connection"""
        holder_info = {
            "connection_id": connection_id,
            "label": label or f"Holder-{len(self.holder_connections) + 1}",
            "connected_at": time.time(),
            "credentials_issued": 0,
            "status": "active"
        }
        self.holder_connections[connection_id] = holder_info
        
        # Set first holder as primary for backward compatibility
        if not self.connection_id:
            self.connection_id = connection_id
            self.holder_connection_id = connection_id
            
        log_msg(f"🎓 New holder connected: {holder_info['label']} ({connection_id})")
        log_msg(f"📊 Total active holders: {len([h for h in self.holder_connections.values() if h['status'] == 'active'])}")

    def remove_holder_connection(self, connection_id, reason="credential_issued"):
        """Remove a holder connection and mark as terminated"""
        if connection_id in self.holder_connections:
            holder_info = self.holder_connections[connection_id]
            holder_info["status"] = "terminated"
            holder_info["terminated_at"] = time.time()
            holder_info["termination_reason"] = reason
            
            log_msg(f"🔌 Terminating connection: {holder_info['label']} ({connection_id}) - {reason}")
            
            # Update primary connection if needed
            if self.connection_id == connection_id:
                active_holders = [conn_id for conn_id, info in self.holder_connections.items() 
                               if info['status'] == 'active']
                self.connection_id = active_holders[0] if active_holders else None
                self.holder_connection_id = self.connection_id
                
            return True
        return False

    async def delayed_termination(self, connection_id):
        """Helper method to terminate connection after a delay"""
        try:
            # Wait a moment for the holder to process the credential
            await asyncio.sleep(2)
            # Terminate the connection
            await self.terminate_holder_connection(connection_id)
        except Exception as e:
            log_msg(f"⚠️ Error in delayed termination: {str(e)}")

    async def terminate_holder_connection(self, connection_id):
        """Actively terminate a holder connection"""
        try:
            # First mark as terminated locally
            self.remove_holder_connection(connection_id, "auto_cleanup")
            
            # Then delete the connection via admin API
            await self.admin_DELETE(f"/connections/{connection_id}")
            log_msg(f"✅ Successfully terminated connection: {connection_id}")
            
        except Exception as e:
            log_msg(f"❌ Error terminating connection {connection_id}: {e}")

    def get_holder_connection_id(self, specific_connection_id=None):
        """Get a holder connection ID for credential issuance"""
        if specific_connection_id and specific_connection_id in self.holder_connections:
            if self.holder_connections[specific_connection_id]['status'] == 'active':
                return specific_connection_id
                
        # Return any active holder connection
        for conn_id, info in self.holder_connections.items():
            if info['status'] == 'active':
                return conn_id
                
        # Fallback to legacy connection tracking
        if self.holder_connection_id:
            return self.holder_connection_id
        elif self.connection_id:
            return self.connection_id
        else:
            log_msg("⚠️ No active holder connections available for credential issuance")
            return None

    def get_active_holders(self):
        """Get list of all active holder connections"""
        return {conn_id: info for conn_id, info in self.holder_connections.items() 
                if info['status'] == 'active'}

    def generate_approval_request(self, student_data):
        """Generate approval request to send to admin"""
        approval_id = str(uuid.uuid4())
        
        request = {
            "type": "credential_approval_request",
            "approval_id": approval_id,
            "student_data": student_data,
            "timestamp": str(int(time.time())),
            "registrar_id": "REG003"
        }
        
        return approval_id, request

    async def send_approval_request(self, student_data):
        """Send credential approval request to admin"""
        if not self.admin_connection_id:
            log_msg("❌ No connection to admin established. Cannot request approval.")
            return None
            
        # Ensure we have a holder connection for future credential issuance
        if not self.get_holder_connection_id():
            log_msg("⚠️ Warning: No holder connection established yet. Credential issuance may fail later.")
            
        approval_id, request = self.generate_approval_request(student_data)
        
        try:
            await self.admin_POST(
                f"/connections/{self.admin_connection_id}/send-message",
                {"content": json.dumps(request)}
            )
            
            # Store the pending request
            self.pending_credentials[approval_id] = {
                "student_data": student_data,
                "request_time": time.time(),
                "status": "pending_approval"
            }
            
            log_msg(f"📤 Approval request sent to admin. Approval ID: {approval_id}")
            return approval_id
            
        except Exception as e:
            log_msg(f"❌ Error sending approval request: {e}")
            return None
    
    # Inside UniRegCAgent
    async def handle_basicmessages(self, payload):
        """Handle incoming basic message webhooks"""
        try:
            content = payload.get("content", "")
            connection_id = payload.get("connection_id", "")
            
            if content:
                # Try to parse content as JSON
                try:
                    content_json = json.loads(content)
                    if isinstance(content_json, dict) and content_json.get("type") == "credential_approval_response":
                        log_msg("Received credential approval response via webhook")
                        await self.handle_approval_response(payload)
                        return
                except json.JSONDecodeError:
                    pass
                
                # Handle as plain text message
                log_msg(f"Received message from {connection_id}: {content}")
                
        except Exception as e:
            log_msg(f"Error handling basicmessage webhook: {e}")

    async def handle_connections(self, payload):
        """Handle connection state changes with multi-holder support"""
        conn_id = payload.get("connection_id")
        state = payload.get("state")
        rfc23_state = payload.get("rfc23_state")
        
        log_msg(f"Connection {conn_id} state: {state}")
        
        if state == "active" and conn_id:
            log_msg(f"✅ Connection {conn_id} is now active")
            
            try:
                # Determine connection type based on context or labels
                connection_info = await self.admin_GET(f"/connections/{conn_id}")
                their_label = connection_info.get("their_label", "")
                alias = connection_info.get("alias", "")
                
                # Check if this is an admin connection
                if "admin" in their_label.lower() or "admin" in alias.lower():
                    self.admin_connection_id = conn_id
                    log_msg(f"🔧 Admin connection established: {conn_id}")
                else:
                    # This is a student/holder connection - add to multi-holder support
                    self.add_holder_connection(conn_id, their_label or alias)
                    
                    # Keep backward compatibility
                    if not self.holder_connection_id:
                        self.holder_connection_id = conn_id
                        self.connection_id = conn_id
                        
            except Exception as e:
                # If we can't get connection info, treat as holder connection
                self.add_holder_connection(conn_id, "Unknown-Holder")
                if not self.holder_connection_id:
                    self.holder_connection_id = conn_id
                    self.connection_id = conn_id
                log_msg(f"Could not determine connection type, treating as holder: {e}")
        
        elif state in ["abandoned", "deleted"] and conn_id:
            # Connection was terminated
            if conn_id in self.holder_connections:
                self.remove_holder_connection(conn_id, f"connection_{state}")
            log_msg(f"🔌 Connection {conn_id} was {state}")

    async def handle_approval_response(self, message_data):
        """Handle approval response from admin"""
        try:
            response = json.loads(message_data.get("content", "{}"))
            if response.get("type") == "credential_approval_response":
                approval_id = response.get("approval_id")
                approved = response.get("approved")
                comments = response.get("comments", "")
                
                if approval_id in self.pending_credentials:
                    self.approval_responses[approval_id] = response
                    
                    status = "APPROVED" if approved else "REJECTED"
                    log_msg(f"\n=== APPROVAL RESPONSE RECEIVED ===")
                    log_msg(f"Approval ID: {approval_id}")
                    log_msg(f"Status: {status}")
                    if comments:
                        log_msg(f"Comments: {comments}")
                    log_msg("=== Use option '6' to process approved credentials ===\n")
                    
                    # Update pending credential status
                    self.pending_credentials[approval_id]["status"] = "approved" if approved else "rejected"
                    self.pending_credentials[approval_id]["response_time"] = time.time()
                    
        except Exception as e:
            log_msg(f"Error handling approval response: {e}")

    async def handle_issue_credential_v2_0(self, payload):
        """Handle credential exchange events with automatic connection cleanup"""
        cred_ex_id = payload.get("cred_ex_id")
        connection_id = payload.get("connection_id")
        state = payload.get("state")
        
        if cred_ex_id and connection_id:
            self.credential_exchanges[cred_ex_id] = connection_id
            
        log_msg(f"🎫 Credential exchange {cred_ex_id}: {state}")
        
        # Handle request-received state (when holder accepts offer)
        if state == "request-received":
            log_status("#17 Issue credential to X")
            try:
                # Get the credential exchange record to extract the credential preview
                cred_ex_record = await self.admin_GET(
                    f"/issue-credential-2.0/records/{cred_ex_id}"
                )
                
                # Try to extract credential preview from the offer
                credential_preview = None
                if cred_ex_record.get("cred_offer"):
                    # Get the credential preview from the original offer
                    if cred_ex_record["cred_offer"].get("credential_preview"):
                        credential_preview = cred_ex_record["cred_offer"]["credential_preview"]
                
                # Build the issue request
                issue_request = {"comment": f"Issuing credential, exchange {cred_ex_id}"}
                if credential_preview:
                    issue_request["credential_preview"] = credential_preview
                
                await self.admin_POST(
                    f"/issue-credential-2.0/records/{cred_ex_id}/issue",
                    issue_request,
                )
                log_msg(f"🎫 Credential issued for exchange {cred_ex_id}")
            except Exception as e:
                log_msg(f"❌ Error during credential issuance: {e}")
                # Fallback to basic issue request
                await self.admin_POST(
                    f"/issue-credential-2.0/records/{cred_ex_id}/issue",
                    {"comment": f"Issuing credential, exchange {cred_ex_id}"},
                )
        
        # Handle credential completion and connection cleanup
        elif state == "done" and connection_id:
            # Credential successfully issued
            if connection_id in self.holder_connections:
                self.holder_connections[connection_id]["credentials_issued"] += 1
                holder_info = self.holder_connections[connection_id]
                
                log_msg(f"✅ Credential successfully issued to {holder_info['label']}")
                log_msg(f"🔄 Auto-terminating connection to prevent bloat...")
                
                # Simple termination without delay to avoid callback issues
                try:
                    await self.terminate_holder_connection(connection_id)
                except Exception as e:
                    log_msg(f"⚠️ Error terminating connection: {str(e)}")
                
        elif state == "abandoned" and cred_ex_id in self.credential_exchanges:
            # Credential exchange failed
            connection_id = self.credential_exchanges[cred_ex_id]
            if connection_id in self.holder_connections:
                holder_info = self.holder_connections[connection_id]
                log_msg(f"❌ Credential exchange failed for {holder_info['label']}")
                # Optionally terminate failed connections after some attempts
                # await self.terminate_holder_connection(connection_id)

    async def process_approved_credential(self, approval_id):
        """Process an approved credential and issue it to student"""
        if approval_id not in self.pending_credentials:
            log_msg(f"No pending credential found for approval ID: {approval_id}")
            return
            
        if approval_id not in self.approval_responses:
            log_msg(f"No approval response found for approval ID: {approval_id}")
            return
            
        approval_response = self.approval_responses[approval_id]
        if not approval_response.get("approved"):
            log_msg(f"Credential was not approved for approval ID: {approval_id}")
            return
            
        # Ensure we have a holder connection
        holder_conn_id = self.get_holder_connection_id()
        if not holder_conn_id:
            log_msg("❌ No holder connection available. Cannot issue credential.")
            return
            
        pending_cred = self.pending_credentials[approval_id]
        student_data = pending_cred["student_data"]
        
        # Generate and send the credential offer
        exchange_tracing = False  # You can make this configurable
        
        try:
            # Use the credential generation logic with holder connection
            offer_request = self.generate_credential_offer(
                20,  # Assuming AIP 20
                CRED_FORMAT_INDY,  # Assuming Indy format
                self.cred_def_id,
                exchange_tracing,
                student_data=student_data,
                holder_connection_id=holder_conn_id  # Pass holder connection explicitly
            )
            
            await self.admin_POST(
                "/issue-credential-2.0/send-offer", offer_request
            )
            
            log_msg(f"✅ Credential offer sent to holder (Connection: {holder_conn_id}) for approval ID: {approval_id}")
            
            # Clean up processed credential
            del self.pending_credentials[approval_id]
            del self.approval_responses[approval_id]
            
        except Exception as e:
            log_msg(f"❌ Error processing approved credential: {e}")

    async def process_approved_credential_for_holder(self, approval_id, target_conn_id):
        """Process an approved credential and issue it to a specific holder"""
        if approval_id not in self.pending_credentials:
            log_msg(f"No pending credential found for approval ID: {approval_id}")
            return
            
        if approval_id not in self.approval_responses:
            log_msg(f"No approval response found for approval ID: {approval_id}")
            return
            
        approval_response = self.approval_responses[approval_id]
        if not approval_response.get("approved"):
            log_msg(f"Credential was not approved for approval ID: {approval_id}")
            return
            
        # Validate the target connection exists and is active
        active_holders = self.get_active_holders()
        if target_conn_id not in active_holders:
            log_msg(f"❌ Target holder connection {target_conn_id} is not active.")
            return
            
        pending_cred = self.pending_credentials[approval_id]
        student_data = pending_cred["student_data"]
        
        # Generate and send the credential offer to specific holder
        exchange_tracing = False  # You can make this configurable
        
        try:
            # Use the credential generation logic with specific holder connection
            offer_request = self.generate_credential_offer(
                20,  # Assuming AIP 20
                CRED_FORMAT_INDY,  # Assuming Indy format
                self.cred_def_id,
                exchange_tracing,
                student_data=student_data,
                holder_connection_id=target_conn_id  # Pass specific holder connection
            )
            
            await self.admin_POST(
                "/issue-credential-2.0/send-offer", offer_request
            )
            
            holder_info = active_holders[target_conn_id]
            log_msg(f"✅ Credential offer sent to {holder_info['label']} (Connection: {target_conn_id}) for approval ID: {approval_id}")
            
            # Clean up processed credential
            del self.pending_credentials[approval_id]
            del self.approval_responses[approval_id]
            
        except Exception as e:
            log_msg(f"❌ Error processing approved credential for specific holder: {e}")

    def generate_credential_offer(self, aip, cred_type, cred_def_id, exchange_tracing, student_data=None, holder_connection_id=None):
        # Use provided student data or default values
        if student_data:
            cred_attrs = student_data
        else:
            cred_attrs = {
                "student_id": "ST12345",
                "student_name": "John Doe",
                "university_name": "Demo University",
                "graduation_year": "2024",
                "cgpa": "3.75",
            }
            
        # Determine which connection to use for credential issuance
        target_connection_id = holder_connection_id or self.get_holder_connection_id()
        
        if not target_connection_id:
            raise Exception("❌ No holder connection available for credential offer")
            
        log_msg(f"📋 Generating credential offer for holder connection: {target_connection_id}")
        
        if aip == 10:
            self.cred_attrs[cred_def_id] = cred_attrs
            cred_preview = {
                "@type": CRED_PREVIEW_TYPE,
                "attributes": [
                    {"name": n, "value": v}
                    for (n, v) in self.cred_attrs[cred_def_id].items()
                ],
            }
            offer_request = {
                "connection_id": target_connection_id,  # Use holder connection
                "cred_def_id": cred_def_id,
                "comment": f"University Registration offer on cred def id {cred_def_id}",
                "auto_remove": False,
                "credential_preview": cred_preview,
                "trace": exchange_tracing,
            }
            return offer_request

        elif aip == 20:
            if cred_type == CRED_FORMAT_INDY:
                self.cred_attrs[cred_def_id] = cred_attrs
                cred_preview = {
                    "@type": CRED_PREVIEW_TYPE,
                    "attributes": [
                        {"name": n, "value": v}
                        for (n, v) in self.cred_attrs[cred_def_id].items()
                    ],
                }
                offer_request = {
                            "connection_id": target_connection_id,  # Use holder connection
                            "comment": f"University Registration offer on cred def id {cred_def_id}",
                            "auto_remove": False,
                            "credential_preview": cred_preview,
                            "filter": {"indy": {"cred_def_id": cred_def_id}},
                            "trace": exchange_tracing,
                        }
                return offer_request

            elif cred_type == CRED_FORMAT_JSON_LD:
                # Use student data in JSON-LD credential
                given_name = cred_attrs.get("student_name", "JOHN").split()[0].upper()
                family_name = cred_attrs.get("student_name", "DOE").split()[-1].upper()
                
                offer_request = {
                    "connection_id": target_connection_id,  # Use holder connection
                    "filter": {
                        "ld_proof": {
                            "credential": {
                                "@context": [
                                    "https://www.w3.org/2018/credentials/v1",
                                    "https://w3id.org/citizenship/v1",
                                    "https://w3id.org/security/bbs/v1",
                                ],
                                "type": [
                                    "VerifiableCredential",
                                    "UniversityStudent",
                                ],
                                "id": "https://credential.example.com/students/1234567890",
                                "issuer": self.did,
                                "issuanceDate": "2020-01-01T12:00:00Z",
                                "credentialSubject": {
                                    "type": ["UniversityStudent"],
                                    "givenName": given_name,
                                    "familyName": family_name,
                                    "universityName": cred_attrs.get("university_name", "Demo University"),
                                    "graduationYear": cred_attrs.get("graduation_year", "2024"),
                                    "cgpa": cred_attrs.get("cgpa", "3.75"),
                                },
                            },
                            "options": {"proofType": SIG_TYPE_BLS},
                        }
                    },
                }
                return offer_request
            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")
        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")

    def generate_proof_request_web_request(
        self, aip, cred_type, revocation, exchange_tracing, connectionless=False
    ):
        # Get the holder connection for proof requests
        target_connection_id = self.get_holder_connection_id()
        
        if aip == 10:
            req_attrs = [
                {
                    "name": "student_id",
                    "restrictions": [{"schema_name": "university_registration_schema"}],
                },
                {
                    "name": "student_name",
                    "restrictions": [{"schema_name": "university_registration_schema"}],
                },
                {
                    "name": "university_name",
                    "restrictions": [{"schema_name": "university_registration_schema"}],
                },
                {
                    "name": "graduation_year",
                    "restrictions": [{"schema_name": "university_registration_schema"}],
                },
            ]
            if revocation:
                req_attrs.append(
                    {
                        "name": "cgpa",
                        "restrictions": [{"schema_name": "university_registration_schema"}],
                        "non_revoked": {"to": int(time.time() - 1)},
                    },
                )
            else:
                req_attrs.append(
                    {
                        "name": "cgpa",
                        "restrictions": [{"schema_name": "university_registration_schema"}],
                    }
                )
            if SELF_ATTESTED:
                req_attrs.append(
                    {"name": "self_attested_thing"},
                )
            req_preds = []
            indy_proof_request = {
                "name": "Proof of University Registration",
                "version": "1.0",
                "requested_attributes": {
                    f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                },
                "requested_predicates": {
                    f"0_{req_pred['name']}_GE_uuid": req_pred for req_pred in req_preds
                },
            }
            if revocation:
                indy_proof_request["non_revoked"] = {"to": int(time.time())}
            proof_request_web_request = {
                "proof_request": indy_proof_request,
                "trace": exchange_tracing,
            }
            if not connectionless and target_connection_id:
                proof_request_web_request["connection_id"] = target_connection_id
            return proof_request_web_request

        elif aip == 20:
            if cred_type == CRED_FORMAT_INDY:
                req_attrs = [
                    {
                        "name": "student_id",
                        "restrictions": [{"schema_name": "university_registration_schema"}],
                    },
                    {
                        "name": "student_name",
                        "restrictions": [{"schema_name": "university_registration_schema"}],
                    },
                    {
                        "name": "university_name",
                        "restrictions": [{"schema_name": "university_registration_schema"}],
                    },
                    {
                        "name": "graduation_year",
                        "restrictions": [{"schema_name": "university_registration_schema"}],
                    },
                ]
                if revocation:
                    req_attrs.append(
                        {
                            "name": "cgpa",
                            "restrictions": [{"schema_name": "university_registration_schema"}],
                            "non_revoked": {"to": int(time.time() - 1)},
                        },
                    )
                else:
                    req_attrs.append(
                        {
                            "name": "cgpa",
                            "restrictions": [{"schema_name": "university_registration_schema"}],
                        }
                    )
                if SELF_ATTESTED:
                    req_attrs.append(
                        {"name": "self_attested_thing"},
                    )
                req_preds = []
                indy_proof_request = {
                    "name": "Proof of University Registration",
                    "version": "1.0",
                    "requested_attributes": {
                        f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                    },
                    "requested_predicates": {
                        f"0_{req_pred['name']}_GE_uuid": req_pred
                        for req_pred in req_preds
                    },
                }
                if revocation:
                    indy_proof_request["non_revoked"] = {"to": int(time.time())}
                proof_request_web_request = {
                    "presentation_request": {"indy": indy_proof_request},
                    "trace": exchange_tracing,
                }
                if not connectionless and target_connection_id:
                    proof_request_web_request["connection_id"] = target_connection_id
                return proof_request_web_request

            elif cred_type == CRED_FORMAT_JSON_LD:
                proof_request_web_request = {
                    "comment": "test proof request for university registration json-ld",
                    "presentation_request": {
                        "dif": {
                            "options": {
                                "challenge": "3fa85f64-5717-4562-b3fc-2c963f66afa7",
                                "domain": "4jt78h47fh47",
                            },
                            "presentation_definition": {
                                "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
                                "format": {"ldp_vp": {"proof_type": [SIG_TYPE_BLS]}},
                                "input_descriptors": [
                                    {
                                        "id": "university_input_1",
                                        "name": "University Student Credential",
                                        "schema": [
                                            {
                                                "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
                                            },
                                            {
                                                "uri": "https://w3id.org/citizenship#UniversityStudent"
                                            },
                                        ],
                                        "constraints": {
                                            "limit_disclosure": "required",
                                            "is_holder": [
                                                {
                                                    "directive": "required",
                                                    "field_id": [
                                                        "1f44d55f-f161-4938-a659-f8026467f126"
                                                    ],
                                                }
                                            ],
                                            "fields": [
                                                {
                                                    "id": "1f44d55f-f161-4938-a659-f8026467f126",
                                                    "path": [
                                                        "$.credentialSubject.familyName"
                                                    ],
                                                    "purpose": "The claim must be from one of the specified person",
                                                    "filter": {"const": "DOE"},
                                                },
                                                {
                                                    "path": [
                                                        "$.credentialSubject.givenName"
                                                    ],
                                                    "purpose": "The claim must be from one of the specified person",
                                                },
                                            ],
                                        },
                                    }
                                ],
                            },
                        }
                    },
                }
                if not connectionless and target_connection_id:
                    proof_request_web_request["connection_id"] = target_connection_id
                return proof_request_web_request
            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")
        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")


async def main(args):
    extra_args = None
    if DEMO_EXTRA_AGENT_ARGS:
        extra_args = json.loads(DEMO_EXTRA_AGENT_ARGS)
        print("Got extra args:", extra_args)

    # Fix Docker networking - when running in Docker containers, set correct endpoint
    import os
    if os.path.exists("/.dockerenv"):  # We're running inside a Docker container
        log_msg("Detected Docker container environment")
        # Set the external host to Docker bridge gateway for proper networking
        os.environ["RUNMODE"] = "docker"
        os.environ["DOCKERHOST"] = "172.17.0.1"
        # Set the correct endpoint to eliminate localhost errors - using port 8110 for uni_reg_c
        os.environ["AGENT_ENDPOINT"] = "http://172.17.0.1:8110"
        log_msg("Set RUNMODE=docker, DOCKERHOST=172.17.0.1, and AGENT_ENDPOINT for container networking")

    uni_reg_c_agent = await create_agent_with_args(
        args,
        ident="uni_reg_c",
        extra_args=extra_args,
    )

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {uni_reg_c_agent.wallet_type})"
                if uni_reg_c_agent.wallet_type
                else ""
            )
        )
        agent = UniRegCAgent(
            "uni_reg_c.agent",
            uni_reg_c_agent.start_port,
            uni_reg_c_agent.start_port + 1,
            genesis_data=uni_reg_c_agent.genesis_txns,
            genesis_txn_list=uni_reg_c_agent.genesis_txn_list,
            no_auto=uni_reg_c_agent.no_auto,
            tails_server_base_url=uni_reg_c_agent.tails_server_base_url,
            revocation=uni_reg_c_agent.revocation,
            timing=uni_reg_c_agent.show_timing,
            multitenant=uni_reg_c_agent.multitenant,
            mediation=uni_reg_c_agent.mediation,
            wallet_type=uni_reg_c_agent.wallet_type,
            seed=uni_reg_c_agent.seed,
            aip=uni_reg_c_agent.aip,
            endorser_role=uni_reg_c_agent.endorser_role,
            anoncreds_legacy_revocation=uni_reg_c_agent.anoncreds_legacy_revocation,
            log_file=uni_reg_c_agent.log_file,
            log_config=uni_reg_c_agent.log_config,
            log_level=uni_reg_c_agent.log_level,
            reuse_connections=uni_reg_c_agent.reuse_connections,
            multi_use_invitations=uni_reg_c_agent.multi_use_invitations,
            public_did_connections=uni_reg_c_agent.public_did_connections,
            extra_args=extra_args,
        )

        uni_reg_c_schema_name = "university_registration_schema"
        uni_reg_c_schema_attrs = [
            "student_id",
            "student_name",
            "university_name",
            "graduation_year",
            "cgpa",
        ]
        if uni_reg_c_agent.cred_type == CRED_FORMAT_INDY:
            uni_reg_c_agent.public_did = True
            await uni_reg_c_agent.initialize(
                the_agent=agent,
                schema_name=uni_reg_c_schema_name,
                schema_attrs=uni_reg_c_schema_attrs,
                create_endorser_agent=(
                    (uni_reg_c_agent.endorser_role == "author")
                    if uni_reg_c_agent.endorser_role
                    else False
                ),
            )
            log_msg("Agent initialized successfully")
            
            # Set the credential definition ID for the agent instance
            agent.cred_def_id = uni_reg_c_agent.cred_def_id
            log_msg(f"Set agent cred_def_id: {agent.cred_def_id}")
            
        elif uni_reg_c_agent.cred_type == CRED_FORMAT_JSON_LD:
            uni_reg_c_agent.public_did = True
            await uni_reg_c_agent.initialize(the_agent=agent)
            # Set the credential definition ID for JSON-LD as well (if available)
            if hasattr(uni_reg_c_agent, 'cred_def_id'):
                agent.cred_def_id = uni_reg_c_agent.cred_def_id
                log_msg(f"Set agent cred_def_id: {agent.cred_def_id}")
        else:
            raise Exception("Invalid credential type:" + uni_reg_c_agent.cred_type)

        # Webhook handling is automatically handled by the agent's built-in webhook server
        # The agent will call our handle_webhook method when webhooks are received

        # Generate an invitation for students
        await uni_reg_c_agent.generate_invitation(
            display_qr=True,
            reuse_connections=uni_reg_c_agent.reuse_connections,
            multi_use_invitations=uni_reg_c_agent.multi_use_invitations,
            public_did_connections=uni_reg_c_agent.public_did_connections, 
            wait=False,
        )
        
        log_msg("Agent ready to process credential approval responses from admin")
        exchange_tracing = False
        options = (
            "    (1) Request Credential Approval from Admin\n"
            "    (2) Send Proof Request\n"
            "    (2a) Send *Connectionless* Proof Request (requires a Mobile client)\n"
            "    (3) Send Message\n"
            "    (4) Create New Invitation\n"
            "    (5) Connect to Admin Agent\n"
            "    (6) Process Approved Credentials\n"
            "    (7) List Pending Approvals\n"
        )
        if uni_reg_c_agent.revocation:
            options += (
                "    (8) Revoke Credential\n"
                "    (9) Publish Revocations\n"
                "    (10) Rotate Revocation Registry\n"
                "    (11) List Revocation Registries\n"
            )
        if uni_reg_c_agent.endorser_role and uni_reg_c_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        if uni_reg_c_agent.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (T) Toggle tracing on credential/proof exchange\n"
        options += "    (X) Exit?\n[1/2/3/4/5/6/7/{}{}T/X] ".format(
            "8/9/10/11/" if uni_reg_c_agent.revocation else "",
            "W/" if uni_reg_c_agent.multitenant else "",
        )

        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "dD" and uni_reg_c_agent.endorser_role:
                endorser_did = await prompt("Enter Endorser's DID: ")
                await uni_reg_c_agent.agent.admin_POST(
                    f"/transactions/{uni_reg_c_agent.agent.connection_id}/set-endorser-info",
                    params={"endorser_did": endorser_did},
                )

            elif option in "wW" and uni_reg_c_agent.multitenant:
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = await prompt(
                    "(Y/N) Create sub-wallet webhook target: "
                )
                if include_subwallet_webhook.lower() == "y":
                    created = await uni_reg_c_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        webhook_port=uni_reg_c_agent.agent.get_new_webhook_port(),
                        public_did=True,
                        mediator_agent=uni_reg_c_agent.mediator_agent,
                        endorser_agent=uni_reg_c_agent.endorser_agent,
                        taa_accept=uni_reg_c_agent.taa_accept,
                    )
                else:
                    created = await uni_reg_c_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        public_did=True,
                        mediator_agent=uni_reg_c_agent.mediator_agent,
                        endorser_agent=uni_reg_c_agent.endorser_agent,
                        cred_type=uni_reg_c_agent.cred_type,
                        taa_accept=uni_reg_c_agent.taa_accept,
                    )
                if created:
                    await uni_reg_c_agent.create_schema_and_cred_def(
                        schema_name=uni_reg_c_schema_name,
                        schema_attrs=uni_reg_c_schema_attrs,
                    )

            elif option in "tT":
                exchange_tracing = not exchange_tracing
                log_msg(
                    ">>> Credential/Proof Exchange Tracing is {}".format(
                        "ON" if exchange_tracing else "OFF"
                    )
                )

            elif option == "1":
                log_status("#13 Request credential approval from admin")
                
                if not agent.admin_connection_id:
                    log_msg("No connection to admin established. Please use option 5 first.")
                    continue

                # Collect student information
                student_id = await prompt("Enter student ID: ")
                student_name = await prompt("Enter student name: ")
                university_name = await prompt("Enter university name: ")
                graduation_year = await prompt("Enter graduation year: ")
                cgpa = await prompt("Enter CGPA: ")
                
                student_data = {
                    "student_id": student_id,
                    "student_name": student_name,
                    "university_name": university_name,
                    "graduation_year": graduation_year,
                    "cgpa": cgpa,
                }
                
                approval_id = await agent.send_approval_request(student_data)
                if approval_id:
                    log_msg(f"Approval request sent. Waiting for admin response...")

            elif option == "2":
                log_status("#20 Request proof of university registration from student")
                if uni_reg_c_agent.aip == 10:
                    proof_request_web_request = (
                        agent.generate_proof_request_web_request(
                            uni_reg_c_agent.aip,
                            uni_reg_c_agent.cred_type,
                            uni_reg_c_agent.revocation,
                            exchange_tracing,
                        )
                    )
                    await agent.admin_POST(
                        "/present-proof/send-request", proof_request_web_request
                    )
                elif uni_reg_c_agent.aip == 20:
                    if uni_reg_c_agent.cred_type == CRED_FORMAT_INDY:
                        proof_request_web_request = (
                            agent.generate_proof_request_web_request(
                                uni_reg_c_agent.aip,
                                uni_reg_c_agent.cred_type,
                                uni_reg_c_agent.revocation,
                                exchange_tracing,
                            )
                        )
                    elif uni_reg_c_agent.cred_type == CRED_FORMAT_JSON_LD:
                        proof_request_web_request = (
                            agent.generate_proof_request_web_request(
                                uni_reg_c_agent.aip,
                                uni_reg_c_agent.cred_type,
                                uni_reg_c_agent.revocation,
                                exchange_tracing,
                            )
                        )
                    else:
                        raise Exception(
                            "Error invalid credential type:" + uni_reg_c_agent.cred_type
                        )

                    await agent.admin_POST(
                        "/present-proof-2.0/send-request", proof_request_web_request
                    )
                else:
                    raise Exception(f"Error invalid AIP level: {uni_reg_c_agent.aip}")

            elif option == "2a":
                log_status("#20 Request * Connectionless * proof of university registration from student")
                if uni_reg_c_agent.aip == 10:
                    proof_request_web_request = (
                        agent.generate_proof_request_web_request(
                            uni_reg_c_agent.aip,
                            uni_reg_c_agent.cred_type,
                            uni_reg_c_agent.revocation,
                            exchange_tracing,
                            connectionless=True,
                        )
                    )
                    proof_request = await agent.admin_POST(
                        "/present-proof/create-request", proof_request_web_request
                    )
                    pres_req_id = proof_request["presentation_exchange_id"]
                    url = (
                        os.getenv("WEBHOOK_TARGET")
                        or (
                            "http://"
                            + os.getenv("DOCKERHOST").replace(
                                "{PORT}", str(agent.admin_port + 1)
                            )
                            + "/webhooks"
                        )
                    ) + f"/pres_req/{pres_req_id}/"
                    log_msg(f"Proof request url: {url}")
                    qr = QRCode(border=1)
                    qr.add_data(url)
                    log_msg(
                        "Scan the following QR code to accept the proof request from a mobile agent."
                    )
                    qr.print_ascii(invert=True)
                else:
                    raise Exception(f"Error invalid AIP level: {uni_reg_c_agent.aip}")

            elif option == "3":
                msg = await prompt("Enter message: ")
                if agent.get_holder_connection_id():
                    await agent.admin_POST(
                        f"/connections/{agent.get_holder_connection_id()}/send-message",
                        {"content": msg},
                    )
                else:
                    log_msg("No student connection established.")

            elif option == "4":
                log_msg(
                    "Creating a new invitation, please receive "
                    "and accept this invitation using student agent"
                )
                await uni_reg_c_agent.generate_invitation(
                    display_qr=True,
                    reuse_connections=uni_reg_c_agent.reuse_connections,
                    multi_use_invitations=uni_reg_c_agent.multi_use_invitations,
                    public_did_connections=uni_reg_c_agent.public_did_connections,
                    wait=False,
                )
                log_msg("📱 QR code generated! Scan with mobile agent to connect.")
                log_msg("🔄 Connection will be tracked automatically when established.")

            elif option == "5":
                log_msg("Please provide admin agent invitation")
                log_msg("Paste the admin invitation JSON and press Enter:")
                
                invitation_json = await prompt("")
                invitation_json = invitation_json.strip().replace("\n", "").replace("\r", "")
                try:
                    # Parse and validate the invitation
                    invitation = json.loads(invitation_json)
                    
                    log_msg(f"Received invitation: {json.dumps(invitation, indent=2)}")
                    
                    # Handle Docker container networking
                    if "services" in invitation and len(invitation["services"]) > 0:
                        service = invitation["services"][0]
                        if "serviceEndpoint" in service:
                            endpoint = service["serviceEndpoint"]
                            log_msg(f"Original endpoint: {endpoint}")
                            
                            # When running in Docker containers via run_demo, convert localhost appropriately
                            if "localhost" in endpoint:
                                # For Linux Docker, use the bridge gateway IP
                                docker_gateway = "172.17.0.1"  # Default Docker bridge gateway on Linux
                                docker_endpoint = endpoint.replace("localhost", docker_gateway)
                                
                                # Also try container name as alternative
                                container_endpoint = endpoint.replace("localhost", "uni_admin_c")
                                
                                service["serviceEndpoint"] = docker_endpoint
                                log_msg(f"Converted to Docker bridge endpoint: {docker_endpoint}")
                                log_msg(f"Alternative container endpoint: {container_endpoint}")
                                log_msg("(Both agents running in Docker containers)")
                                
                                # Test connectivity to both options
                                import socket
                                endpoints_to_test = [
                                    (docker_endpoint, "Docker bridge gateway"),
                                    (container_endpoint, "Container name")
                                ]
                                
                                for test_endpoint, description in endpoints_to_test:
                                    try:
                                        host, port_str = test_endpoint.replace("http://", "").replace("https://", "").split(":")
                                        port = int(port_str)
                                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                        sock.settimeout(2)
                                        result = sock.connect_ex((host, port))
                                        sock.close()
                                        if result == 0:
                                            log_msg(f"✅ {description} endpoint {test_endpoint} is reachable")
                                            service["serviceEndpoint"] = test_endpoint
                                            break
                                        else:
                                            log_msg(f"❌ {description} endpoint {test_endpoint} is NOT reachable")
                                    except Exception as e:
                                        log_msg(f"❌ Could not test {description} endpoint: {e}")
                                else:
                                    log_msg("⚠️  Using Docker bridge gateway endpoint (may still work)")
                                    service["serviceEndpoint"] = docker_endpoint
                            else:
                                log_msg(f"Using endpoint as-is: {endpoint}")
                    
                    # Use out-of-band invitation handling
                    response = await agent.admin_POST("/out-of-band/receive-invitation", invitation)
                    
                    agent.admin_connection_id = response["connection_id"]
                    log_msg(f"✅ Connected to admin agent: {agent.admin_connection_id}")
                    
                    # Verify connection state
                    await asyncio.sleep(2)
                    try:
                        connection = await agent.admin_GET(f"/connections/{agent.admin_connection_id}")
                        log_msg(f"Connection state: {connection.get('state', 'unknown')}")
                        log_msg("You can now use option 1 to request credential approvals")
                    except Exception as e:
                        log_msg(f"Could not verify connection state: {e}")
                    
                except json.JSONDecodeError as e:
                    log_msg(f"❌ Invalid JSON format: {str(e)}")
                except KeyError as e:
                    log_msg(f"❌ Missing expected key: {str(e)}")
                except Exception as e:
                    log_msg(f"❌ Connection error: {str(e)}")
                    log_msg("Troubleshooting tips:")
                    log_msg("1. Make sure admin agent is running on the correct port")
                    log_msg("2. Check that admin agent shows 'Admin agent started' message")
                    log_msg("3. Verify admin agent is using --port 8120")
                    log_msg("4. Try restarting admin agent if needed")

            elif option == "6":
                # Process approved credentials with holder selection
                approved_credentials = [
                    approval_id for approval_id, response in agent.approval_responses.items()
                    if response.get("approved")
                ]
                
                if not approved_credentials:
                    log_msg("No approved credentials to process.")
                    continue
                
                # Show available holders
                active_holders = agent.get_active_holders()
                if not active_holders:
                    log_msg("No active holder connections. Cannot issue credentials.")
                    continue
                
                log_msg("\n=== APPROVED CREDENTIALS ===")
                for i, approval_id in enumerate(approved_credentials, 1):
                    pending_cred = agent.pending_credentials[approval_id]
                    student_data = pending_cred["student_data"]
                    log_msg(f"  {i}. {approval_id}: {student_data.get('student_name')} - {student_data.get('university_name')}")
                
                cred_choice = await prompt("Enter credential number to process: ")
                try:
                    cred_index = int(cred_choice) - 1
                    if cred_index < 0 or cred_index >= len(approved_credentials):
                        log_msg("Invalid credential number.")
                        continue
                    approval_id = approved_credentials[cred_index]
                except ValueError:
                    log_msg("Please enter a valid number.")
                    continue
                
                log_msg("\n=== ACTIVE HOLDER CONNECTIONS ===")
                holder_list = list(active_holders.items())
                for i, (conn_id, info) in enumerate(holder_list, 1):
                    log_msg(f"  {i}. {info['label']} ({conn_id})")
                
                holder_choice = await prompt("Enter holder number to send credential to: ")
                try:
                    holder_index = int(holder_choice) - 1
                    if holder_index < 0 or holder_index >= len(holder_list):
                        log_msg("Invalid holder number.")
                        continue
                    target_conn_id = holder_list[holder_index][0]
                except ValueError:
                    log_msg("Please enter a valid number.")
                    continue
                
                # Process credential with specific holder
                await agent.process_approved_credential_for_holder(approval_id, target_conn_id)

            elif option == "7":
                # List pending approvals
                if not agent.pending_credentials:
                    log_msg("No pending approval requests.")
                else:
                    log_msg("\n=== PENDING APPROVAL REQUESTS ===")
                    for approval_id, data in agent.pending_credentials.items():
                        student_data = data["student_data"]
                        status = data["status"]
                        request_time = datetime.datetime.fromtimestamp(data["request_time"])
                        log_msg(f"\nApproval ID: {approval_id}")
                        log_msg(f"Status: {status}")
                        log_msg(f"Request Time: {request_time}")
                        log_msg(f"Student: {student_data.get('student_name')} - {student_data.get('university_name')}")
                        log_msg(f"Graduation Year: {student_data.get('graduation_year')} | CGPA: {student_data.get('cgpa')}")

            elif option == "7a":
                # Multi-holder management
                active_holders = agent.get_active_holders()
                if not active_holders:
                    log_msg("No active holder connections.")
                else:
                    log_msg("\n=== ACTIVE HOLDER CONNECTIONS ===")
                    for conn_id, info in active_holders.items():
                        connected_time = datetime.datetime.fromtimestamp(info["connected_at"])
                        log_msg(f"\nConnection ID: {conn_id}")
                        log_msg(f"Label: {info['label']}")
                        log_msg(f"Connected: {connected_time}")
                        log_msg(f"Credentials Issued: {info['credentials_issued']}")
                        log_msg(f"Status: {info['status']}")
                    
                    # Show terminated connections too
                    terminated = {k: v for k, v in agent.holder_connections.items() 
                                if v['status'] == 'terminated'}
                    if terminated:
                        log_msg(f"\n=== TERMINATED CONNECTIONS ({len(terminated)}) ===")
                        for conn_id, info in list(terminated.items())[-5:]:  # Show last 5
                            terminated_time = datetime.datetime.fromtimestamp(info.get("terminated_at", 0))
                            log_msg(f"{info['label']}: {info.get('termination_reason', 'unknown')} at {terminated_time}")
                    
                    log_msg(f"\n📊 Total connections: {len(agent.holder_connections)}")
                    log_msg(f"📊 Active: {len(active_holders)}")
                    log_msg(f"📊 Terminated: {len(terminated)}")

            elif option == "8" and uni_reg_c_agent.revocation:
                rev_reg_id = (await prompt("Enter revocation registry ID: ")).strip()
                cred_rev_id = (await prompt("Enter credential revocation ID: ")).strip()
                publish = (
                    await prompt("Publish now? [Y/N]: ", default="N")
                ).strip() in "yY"
                
                is_anoncreds = False
                if agent.__dict__["wallet_type"] == "askar-anoncreds":
                    is_anoncreds = True
                try:
                    endpoint = (
                        "/anoncreds/revocation/revoke"
                        if is_anoncreds
                        else "/revocation/revoke"
                    )
                    await agent.admin_POST(
                        endpoint,
                        {
                            "rev_reg_id": rev_reg_id,
                            "cred_rev_id": cred_rev_id,
                            "publish": publish,
                            "connection_id": agent.get_holder_connection_id(),
                            "comment": "Revocation reason goes here ...",
                        },
                    )
                except ClientError:
                    pass

            elif option == "9" and uni_reg_c_agent.revocation:
                try:
                    is_anoncreds = agent.__dict__["wallet_type"] == "askar-anoncreds"
                    endpoint = (
                        "/anoncreds/revocation/publish-revocations"
                        if is_anoncreds
                        else "/revocation/publish-revocations"
                    )
                    resp = await agent.admin_POST(endpoint, {})
                    agent.log(
                        "Published revocations for {} revocation registr{} {}".format(
                            len(resp["rrid2crid"]),
                            "y" if len(resp["rrid2crid"]) == 1 else "ies",
                            json.dumps(list(resp["rrid2crid"]), indent=4),
                        )
                    )
                except ClientError:
                    pass

            elif option == "10" and uni_reg_c_agent.revocation:
                try:
                    is_anoncreds = agent.__dict__["wallet_type"] == "askar-anoncreds"
                    endpoint = (
                        f"/anoncreds/revocation/active-registry/{uni_reg_c_agent.cred_def_id}/rotate"
                        if is_anoncreds
                        else f"/revocation/active-registry/{uni_reg_c_agent.cred_def_id}/rotate"
                    )
                    resp = await agent.admin_POST(endpoint, {})
                    agent.log(
                        "Rotated registries for {}. Decommissioned Registries: {}".format(
                            uni_reg_c_agent.cred_def_id,
                            json.dumps(list(resp["rev_reg_ids"]), indent=4),
                        )
                    )
                except ClientError:
                    pass

            elif option == "11" and uni_reg_c_agent.revocation:
                is_anoncreds = agent.__dict__["wallet_type"] == "askar-anoncreds"
                if is_anoncreds:
                    endpoint = "/anoncreds/revocation/registries"
                    states = [
                        "finished",
                        "failed",
                        "action",
                        "wait",
                        "decommissioned",
                        "full",
                    ]
                    default_state = "finished"
                else:
                    endpoint = "/revocation/registries/created"
                    states = [
                        "init",
                        "generated",
                        "posted",
                        "active",
                        "full",
                        "decommissioned",
                    ]
                    default_state = "active"
                state = (
                    await prompt(
                        f"Filter by state: {states}: ",
                        default=default_state,
                    )
                ).strip()
                if state not in states:
                    state = "active"
                try:
                    resp = await agent.admin_GET(
                        endpoint,
                        params={"state": state},
                    )
                    agent.log(
                        "Registries (state = '{}'): {}".format(
                            state,
                            json.dumps(list(resp["rev_reg_ids"]), indent=4),
                        )
                    )
                except ClientError:
                    pass

        if uni_reg_c_agent.show_timing:
            timing = await agent.fetch_timing()
            if timing:
                for line in agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await uni_reg_c_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="uni_reg_c", port=8110)
    args = parser.parse_args()

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_CONTROLLER_PORT = int(
        os.getenv("PYDEVD_PYCHARM_CONTROLLER_PORT", 5001)
    )

    if ENABLE_PYDEVD_PYCHARM:
        try:
            import pydevd_pycharm

            print(
                "UniRegC remote debugging to "
                f"{PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_CONTROLLER_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_CONTROLLER_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            print("pydevd_pycharm library was not found")

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)