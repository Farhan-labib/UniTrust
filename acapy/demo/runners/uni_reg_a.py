#!/usr/bin/env python3
import asyncio
import datetime
import json
import logging
import os
import sys
import time
from aiohttp import ClientError
from qrcode import QRCode
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from runners.agent_container import (
    AriesAgent,
    arg_parser,
    create_agent_with_args,
)
from runners.support.agent import (
    CRED_FORMAT_INDY,
    CRED_FORMAT_JSON_LD,
    SIG_TYPE_BLS,
)
from runners.support.utils import (
    log_msg,
    log_status,
    prompt,
    prompt_loop,
)

CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))
DEMO_EXTRA_AGENT_ARGS = os.getenv("DEMO_EXTRA_AGENT_ARGS")
DOCKERHOST = os.getenv("DOCKERHOST", "host.docker.internal")

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)

class UniRegAAgent(AriesAgent):
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
        # IMPORTANT: Force no_auto to True to prevent automatic issuance
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="UniRegA",
            no_auto=True,  # Force this to True
            endorser_role=endorser_role,
            revocation=revocation,
            anoncreds_legacy_revocation=anoncreds_legacy_revocation,
            log_file=log_file,
            log_config=log_config,
            log_level=log_level,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = asyncio.Future()
        self.cred_state = {}
        self.cred_attrs = {}
        self.admin_connection_id = None
        self.pending_approvals = {}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    async def handle_connections(self, message):
        """Handle connection state changes"""
        connection_id = message["connection_id"]
        state = message["state"]
        
        self.log(f"Connection {connection_id} in state {state}")
        
        # Handle admin connection
        if connection_id == self.admin_connection_id and state in ("active", "response"):
            log_msg(f"✅ Admin connection established: {connection_id}")
            
        # Handle student connection
        elif state in ("active", "response") and not self.connection_id:
            log_msg(f"🎓 Student connection established: {connection_id}")
            self.connection_id = connection_id
            
            # Mark connection as ready
            if not self._connection_ready.done():
                self._connection_ready.set_result(True)

    def generate_credential_offer(self, aip, cred_type, cred_def_id, exchange_tracing):
        age = 22
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"
        
        if aip == 10:
            self.cred_attrs[cred_def_id] = {
                "student_name": "John Doe",
                "student_id": "STU123456",
                "enrollment_date": "2022-09-01",
                "program": "Computer Science",
                "year": "3",
                "gpa": "3.75",
                "birthdate_dateint": birth_date.strftime(birth_date_format),
                "timestamp": str(int(time.time())),
            }
            cred_preview = {
                "@type": CRED_PREVIEW_TYPE,
                "attributes": [
                    {"name": n, "value": v}
                    for (n, v) in self.cred_attrs[cred_def_id].items()
                ],
            }
            return {
                "connection_id": self.connection_id,
                "cred_def_id": cred_def_id,
                "comment": f"University Registration offer on cred def id {cred_def_id}",
                "auto_remove": False,
                "credential_preview": cred_preview,
                "trace": exchange_tracing,
            }
        elif aip == 20:
            if cred_type == CRED_FORMAT_INDY:
                self.cred_attrs[cred_def_id] = {
                    "student_name": "John Doe",
                    "student_id": "STU123456",
                    "enrollment_date": "2022-09-01",
                    "program": "Computer Science",
                    "year": "3",
                    "gpa": "3.75",
                    "birthdate_dateint": birth_date.strftime(birth_date_format),
                    "timestamp": str(int(time.time())),
                }
                cred_preview = {
                    "@type": CRED_PREVIEW_TYPE,
                    "attributes": [
                        {"name": n, "value": v}
                        for (n, v) in self.cred_attrs[cred_def_id].items()
                    ],
                }
                return {
                    "connection_id": self.connection_id,
                    "comment": f"University Registration offer on cred def id {cred_def_id}",
                    "auto_remove": False,
                    "credential_preview": cred_preview,
                    "filter": {"indy": {"cred_def_id": cred_def_id}},
                    "trace": exchange_tracing,
                }
            elif cred_type == CRED_FORMAT_JSON_LD:
                return {
                    "connection_id": self.connection_id,
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
                                    "givenName": "JOHN",
                                    "familyName": "DOE",
                                    "studentId": "STU123456",
                                    "program": "Computer Science",
                                    "enrollmentDate": "2022-09-01",
                                },
                            },
                            "options": {"proofType": SIG_TYPE_BLS},
                        }
                    },
                }
            else:
                raise Exception(f"Error invalid credential type: {cred_type}")
        else:
            raise Exception(f"Error invalid AIP level: {aip}")

    # Override the base class methods to prevent automatic credential issuance
    async def handle_issue_credential(self, message):
        """Override base class method to prevent automatic credential issuance"""
        state = message.get("state")
        credential_exchange_id = message["credential_exchange_id"]
        prev_state = self.cred_state.get(credential_exchange_id)
        if prev_state == state:
            return  # ignore
        self.cred_state[credential_exchange_id] = state
        
        self.log(
            "Credential: state = {}, credential_exchange_id = {}".format(
                state, credential_exchange_id,
            )
        )
        
        if state == "request_received":
            log_msg(f"🔄 Credential request received for exchange ID: {credential_exchange_id}")
            log_msg(f"⏳ Waiting for admin approval before issuing credential...")
            
            # Get student details
            student_name = "Unknown"
            try:
                record = await self.admin_GET(f"/issue-credential/records/{credential_exchange_id}")
                if "credential_proposal_dict" in record and record["credential_proposal_dict"]:
                    attributes = record["credential_proposal_dict"]["credential_proposal"]["attributes"]
                    student_name = next((attr["value"] for attr in attributes if attr["name"] == "student_name"), "Unknown")
            except Exception as e:
                log_msg(f"⚠️ Could not extract student name: {str(e)}")
                
            # Send approval request to admin - DO NOT AUTO-ISSUE
            await self.send_approval_request(credential_exchange_id, student_name, "issue_credential")
            
        elif state == "credential_acked":
            cred_id = message["credential_id"]
            self.log(f"Stored credential {cred_id} in wallet")
            log_status(f"#18.1 Stored credential {cred_id} in wallet")
            log_msg(f"✅ Credential successfully issued and received for exchange ID: {credential_exchange_id}")
        elif state == "abandoned":
            log_status("Credential exchange abandoned")
            self.log("Problem report message:", message.get("error_msg"))

    async def handle_issue_credential_v2_0(self, message):
        """Override base class method to prevent automatic credential issuance"""
        state = message.get("state")
        cred_ex_id = message["cred_ex_id"]
        prev_state = self.cred_state.get(cred_ex_id)
        if prev_state == state:
            return  # ignore
        self.cred_state[cred_ex_id] = state
        
        self.log(f"Credential: state = {state}, cred_ex_id = {cred_ex_id}")
        
        if state == "request-received":
            log_msg(f"🔄 Credential request received for exchange ID: {cred_ex_id}")
            log_msg(f"⏳ Waiting for admin approval before issuing credential...")
            
            # Get student details
            student_name = "Unknown"
            try:
                record = await self.admin_GET(f"/issue-credential-2.0/records/{cred_ex_id}")
                if "by_format" in record and record["by_format"]:
                    # Try to extract from different possible formats
                    if "cred_offer" in record["by_format"] and record["by_format"]["cred_offer"]:
                        if "indy" in record["by_format"]["cred_offer"]:
                            attrs = record["by_format"]["cred_offer"]["indy"].get("credential_preview", {}).get("attributes", [])
                            student_name = next((attr["value"] for attr in attrs if attr["name"] == "student_name"), "Unknown")
                    # Also try from credential_proposal_dict if available
                    elif "credential_proposal_dict" in record and record["credential_proposal_dict"]:
                        attributes = record["credential_proposal_dict"]["credential_proposal"]["attributes"]
                        student_name = next((attr["value"] for attr in attributes if attr["name"] == "student_name"), "Unknown")
            except Exception as e:
                log_msg(f"⚠️ Could not extract student name: {str(e)}")
                
            # Send approval request to admin - DO NOT AUTO-ISSUE
            await self.send_approval_request(cred_ex_id, student_name, "issue_credential_v2_0")
            
        elif state == "done":
            log_msg(f"✅ Credential successfully issued and received for exchange ID: {cred_ex_id}")
        elif state == "abandoned":
            log_status("Credential exchange abandoned")
            self.log("Problem report message:", message.get("error_msg"))

    async def handle_events(self, event):
        if event["topic"] == "connections":
            await self.handle_connections(event["payload"])
        elif event["topic"] == "basicmessages":
            msg = event["payload"]
            if msg["connection_id"] == self.admin_connection_id:
                await self.handle_admin_message(msg["content"])
        
        # Let the overridden methods handle credential events
        elif event["topic"] == "issue_credential":
            await self.handle_issue_credential(event["payload"])
        elif event["topic"] == "issue_credential_v2_0":
            await self.handle_issue_credential_v2_0(event["payload"])

    async def handle_admin_message(self, message):
        """
        Handle admin messages such as approval responses.
        """
        try:
            data = json.loads(message)
        except Exception as e:
            log_msg(f"❌ Failed to parse admin message as JSON: {str(e)}")
            return

        # Handle approval response
        if data.get("type") == "approval_response" and data.get("approved"):
            cred_ex_id = data.get("cred_ex_id")
            api_version = data.get("api_version", "v1")

            log_msg(f"🔍 Approval received for cred_ex_id={cred_ex_id}, api_version={api_version}")

            if cred_ex_id in self.pending_approvals:
                try:
                    # Issue credential based on API version
                    if api_version == "v2":
                        log_msg(f"📤 Sending issue request to /issue-credential-2.0/records/{cred_ex_id}/issue")
                        await self.admin_POST(f"/issue-credential-2.0/records/{cred_ex_id}/issue")
                    else:
                        log_msg(f"📤 Sending issue request to /issue-credential/records/{cred_ex_id}/issue")
                        await self.admin_POST(
                            f"/issue-credential/records/{cred_ex_id}/issue",
                            {"comment": "Credential issued after admin approval"}
                        )

                    log_msg(f"✅ Credential issued successfully for cred_ex_id={cred_ex_id}")
                    del self.pending_approvals[cred_ex_id]  # Remove from queue

                except Exception as e:
                    log_msg(f"❌ Error issuing credential for {cred_ex_id}: {str(e)}")
            else:
                log_msg(f"⚠️ Received approval for unknown cred_ex_id={cred_ex_id}")

        elif data.get("type") == "approval_response" and not data.get("approved"):
            cred_ex_id = data.get("cred_ex_id")
            log_msg(f"❌ Approval denied for cred_ex_id={cred_ex_id}")
            if cred_ex_id in self.pending_approvals:
                del self.pending_approvals[cred_ex_id]

        else:
            log_msg(f"ℹ️ Unknown admin message type: {data}")


    async def send_approval_request(self, cred_ex_id, student_name, api_topic):
        if not self.admin_connection_id:
            log_msg("❌ No admin connection to send approval request")
            return
            
        self.pending_approvals[cred_ex_id] = {
            "student_name": student_name,
            "status": "pending",
            "api_topic": api_topic
        }
        
        # Determine API version for the admin
        api_version = "v2" if api_topic == "issue_credential_v2_0" else "v1"
        
        await self.admin_POST(
            f"/connections/{self.admin_connection_id}/send-message",
            {
                "content": json.dumps({
                    "type": "approval_request",
                    "cred_ex_id": cred_ex_id,
                    "student_name": student_name,
                    "api_version": api_version
                })
            }
        )
        
        log_msg(f"📤 Sent approval request for {student_name} to admin (Exchange ID: {cred_ex_id})")

async def main(args):
    extra_args = None
    if DEMO_EXTRA_AGENT_ARGS:
        extra_args = json.loads(DEMO_EXTRA_AGENT_ARGS)
    
    # IMPORTANT: Force no-auto mode to prevent automatic credential issuance
    args.no_auto = True
    
    uni_reg_a_agent = await create_agent_with_args(
        args,
        ident="uni_reg_a",
        extra_args=extra_args,
    )
    
    try:
        log_status("#1 Provision an agent and wallet")
        agent = UniRegAAgent(
            "uni_reg_a.agent",
            uni_reg_a_agent.start_port,
            uni_reg_a_agent.start_port + 1,
            genesis_data=uni_reg_a_agent.genesis_txns,
            genesis_txn_list=uni_reg_a_agent.genesis_txn_list,
            no_auto=True,  # Force no auto
            tails_server_base_url=uni_reg_a_agent.tails_server_base_url,
            revocation=uni_reg_a_agent.revocation,
            timing=uni_reg_a_agent.show_timing,
            multitenant=uni_reg_a_agent.multitenant,
            mediation=uni_reg_a_agent.mediation,
            wallet_type=uni_reg_a_agent.wallet_type,
            seed=uni_reg_a_agent.seed,
            aip=uni_reg_a_agent.aip,
            endorser_role=uni_reg_a_agent.endorser_role,
            anoncreds_legacy_revocation=uni_reg_a_agent.anoncreds_legacy_revocation,
            extra_args=extra_args,
        )
        
        uni_reg_a_schema_name = "university registration schema"
        uni_reg_a_schema_attrs = [
            "student_name", "student_id", "enrollment_date",
            "program", "year", "gpa", "birthdate_dateint", "timestamp"
        ]
        
        if uni_reg_a_agent.cred_type == CRED_FORMAT_INDY:
            uni_reg_a_agent.public_did = True
            await uni_reg_a_agent.initialize(
                the_agent=agent,
                schema_name=uni_reg_a_schema_name,
                schema_attrs=uni_reg_a_schema_attrs,
            )
        elif uni_reg_a_agent.cred_type == CRED_FORMAT_JSON_LD:
            uni_reg_a_agent.public_did = True
            await uni_reg_a_agent.initialize(the_agent=agent)
        else:
            raise Exception("Invalid credential type")
        
        # Connect to admin agent
        log_status("#2 Connect to University Admin")
        log_msg("Paste the FULL admin invitation JSON (from uni_admin_a output):")
        log_msg("Press Enter on an empty line to submit")
        invitation_lines = []
        while True:
            line = await prompt("")
            if line.strip() == "" and invitation_lines:
                break
            if line.strip() != "":
                invitation_lines.append(line.strip())
                
        invitation_json = "".join(invitation_lines).replace("\n", "").replace("\r", "")
        
        try:
            # Parse and validate the invitation
            invitation = json.loads(invitation_json)
            
            # Ensure the invitation has the required structure
            if "services" in invitation and isinstance(invitation["services"], list):
                for service in invitation["services"]:
                    if service.get("type") == "did-communication":
                        if "recipientKeys" not in service:
                            service["recipientKeys"] = []
                        if "serviceEndpoint" not in service:
                            service["serviceEndpoint"] = f"http://{DOCKERHOST.replace('{PORT}', str(uni_reg_a_agent.start_port))}"
                        if "id" not in service:
                            service["id"] = "#inline"
            
            log_msg(f"Processed invitation: {json.dumps(invitation, indent=2)}")
            
            # Use the newer connection method
            try:
                response = await agent.admin_POST("/out-of-band/receive-invitation", invitation)
                agent.admin_connection_id = response["connection_id"]
                log_msg(f"🔗 Admin connection initiated: {agent.admin_connection_id}")
                
                # Also try to manually accept the invitation if needed
                await asyncio.sleep(2)
                try:
                    await agent.admin_POST(f"/didexchange/{agent.admin_connection_id}/accept-invitation")
                    log_msg("🤝 Sent connection acceptance")
                except Exception as e:
                    log_msg(f"⚠️ Note: Could not send accept-invitation (might not be needed): {str(e)}")
                
            except Exception as e:
                log_msg(f"❌ Error with out-of-band invitation, trying legacy method: {str(e)}")
                
                # Fallback to legacy connection method
                try:
                    # Convert out-of-band to legacy format
                    legacy_invitation = {
                        "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation",
                        "@id": invitation["@id"],
                        "label": invitation["label"],
                        "recipientKeys": invitation["services"][0]["recipientKeys"],
                        "serviceEndpoint": invitation["services"][0]["serviceEndpoint"]
                    }
                    
                    response = await agent.admin_POST("/connections/receive-invitation", legacy_invitation)
                    agent.admin_connection_id = response["connection_id"]
                    log_msg(f"🔗 Admin connection initiated (legacy): {agent.admin_connection_id}")
                    
                    # Accept the invitation
                    await asyncio.sleep(1)
                    await agent.admin_POST(f"/connections/{agent.admin_connection_id}/accept-invitation")
                    log_msg("🤝 Sent legacy connection acceptance")
                    
                except Exception as e2:
                    log_msg(f"❌ Both connection methods failed: {str(e2)}")
                    return
            
            # Wait for admin connection to become active
            log_msg("⏳ Waiting for admin connection to establish...")
            max_wait = 30  # 30 seconds timeout
            wait_count = 0
            while wait_count < max_wait:
                try:
                    connection = await agent.admin_GET(f"/connections/{agent.admin_connection_id}")
                    state = connection['state']
                    
                    # Only log state changes to reduce noise
                    if wait_count == 0 or wait_count % 5 == 0:
                        log_msg(f"Admin connection state: {state}")
                    
                    if state in ("active", "response", "completed"):
                        log_msg("✅ Admin connection established successfully!")
                        break
                    elif state == "error":
                        log_msg("❌ Admin connection failed!")
                        break
                        
                    await asyncio.sleep(1)
                    wait_count += 1
                    
                except Exception as e:
                    if wait_count % 5 == 0:  # Only log every 5 attempts
                        log_msg(f"⚠️ Error checking connection: {str(e)}")
                    await asyncio.sleep(1)
                    wait_count += 1
            
            if wait_count >= max_wait:
                log_msg("⏰ Timeout waiting for admin connection, but proceeding...")
                log_msg("💡 You can try the connection again or proceed - some functionality may be limited")
            
        except json.JSONDecodeError as e:
            log_msg(f"❌ Invalid JSON format: {str(e)}")
            return
        except KeyError as e:
            log_msg(f"❌ Missing expected key: {str(e)}")
            return
        except Exception as e:
            log_msg(f"❌ Unexpected error: {str(e)}")
            log_msg(f"Error details: {str(e.__cause__) if hasattr(e, '__cause__') else 'No additional details'}")
            return
                
        # Generate invitation for students
        log_status("#3 Generate invitation for students")
        await uni_reg_a_agent.generate_invitation(
            display_qr=True,
            reuse_connections=uni_reg_a_agent.reuse_connections,
            wait=True,
        )
        
        options = (
            "    (1) Issue University Registration Credential\n"
            "    (2) Send Proof Request\n"
            "    (3) Send Message\n"
            "    (4) Create New Invitation\n"
            "    (5) Show Pending Approvals\n"
            "    (6) Show Connection Status\n"
            "    (X) Exit?\n[1/2/3/4/5/6/X] "
        )
        
        async for option in prompt_loop(options):
            if option is None or option in "xX":
                break
                
            option = option.strip()
            
            if option == "1":
                if not agent.connection_id:
                    log_msg("❌ No student connection available. Please wait for a student to connect first.")
                    continue

                log_status("Issue university registration credential")
                log_msg("🔄 Sending credential offer - admin approval required before issuance")

                # Only send the offer if we haven't already sent one
                if not hasattr(agent, "last_offer_ex_id"):
                    offer_request = agent.generate_credential_offer(
                        uni_reg_a_agent.aip,
                        uni_reg_a_agent.cred_type,
                        uni_reg_a_agent.cred_def_id,
                        False,
                    )
                    response = await agent.admin_POST("/issue-credential-2.0/send-offer", offer_request)
                    
                    # Store the cred_ex_id for later
                    agent.last_offer_ex_id = response["cred_ex_id"]
                    log_msg(f"📨 Credential offer sent - Exchange ID: {agent.last_offer_ex_id}")
                    log_msg("Awaiting admin approval before issuance...")
                else:
                    log_msg(f"⚠️ Offer already sent with cred_ex_id={agent.last_offer_ex_id}")

            
            elif option == "2":
                log_status("Request proof of university registration")
                # Proof request implementation here
                log_msg("Proof request functionality not implemented yet")
            
            elif option == "3":
                if not agent.connection_id:
                    log_msg("❌ No active student connection")
                    continue
                    
                msg = await prompt("Enter message: ")
                await agent.admin_POST(
                    f"/connections/{agent.connection_id}/send-message",
                    {"content": msg},
                )
                log_msg("📤 Message sent to student")
            
            elif option == "4":
                log_msg("🔄 Creating new invitation...")
                await uni_reg_a_agent.generate_invitation(
                    display_qr=True,
                    reuse_connections=uni_reg_a_agent.reuse_connections,
                    wait=True,
                )
            
            elif option == "5":
                if not agent.pending_approvals:
                    log_msg("📭 No pending approvals")
                else:
                    log_msg("📋 Pending approvals:")
                    for cred_ex_id, details in agent.pending_approvals.items():
                        log_msg(f"  🔄 {cred_ex_id}: {details['student_name']} ({details['status']})")
            
            elif option == "6":
                log_msg("🔗 Connection Status:")
                if agent.admin_connection_id:
                    try:
                        admin_conn = await agent.admin_GET(f"/connections/{agent.admin_connection_id}")
                        log_msg(f"  👨‍💼 Admin: {agent.admin_connection_id} ({admin_conn['state']})")
                    except:
                        log_msg(f"  👨‍💼 Admin: {agent.admin_connection_id} (error retrieving status)")
                else:
                    log_msg("  👨‍💼 Admin: Not connected")
                
                if agent.connection_id:
                    try:
                        student_conn = await agent.admin_GET(f"/connections/{agent.connection_id}")
                        log_msg(f"  🎓 Student: {agent.connection_id} ({student_conn['state']})")
                    except:
                        log_msg(f"  🎓 Student: {agent.connection_id} (error retrieving status)")
                else:
                    log_msg("  🎓 Student: Not connected")
                
    finally:
        terminated = await uni_reg_a_agent.terminate()
        # Small pause to let callbacks finish
        await asyncio.sleep(0.1)
        if not terminated:
            # Return non-zero exit code without killing interpreter
            import sys
            sys.exit(1)

if __name__ == "__main__":
    parser = arg_parser(ident="uni_reg_a", port=8060)
    args = parser.parse_args()
    
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main(args))
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user. Shutting down...")
    finally:
        # Cancel all remaining tasks
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        try:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        # Shutdown async generators cleanly
        loop.run_until_complete(loop.shutdown_asyncgens())
        # Finally close the loop
        loop.close()
        print("✅ Event loop closed cleanly")
