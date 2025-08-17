#!/usr/bin/env python3
import asyncio
import datetime
import json
import logging
import os
import sys
import time
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

SELF_ATTESTED = os.getenv("SELF_ATTESTED")
DEMO_EXTRA_AGENT_ARGS = os.getenv("DEMO_EXTRA_AGENT_ARGS")

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class CompanyAAgent(AriesAgent):
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
            prefix="CompanyA",
            no_auto=no_auto,
            endorser_role=endorser_role,
            revocation=revocation,
            anoncreds_legacy_revocation=anoncreds_legacy_revocation,
            log_file=log_file,
            log_config=log_config,
            log_level=log_level,
            **kwargs,
        )
        self.holder_connections = {}  # Store multiple holder connections
        self.proof_requests = {}  # Store sent proof requests
        self.verified_proofs = {}  # Store verified proofs
        self._connection_ready = None

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    def add_holder_connection(self, connection_id, alias=None):
        """Add a new holder connection"""
        self.holder_connections[connection_id] = {
            "alias": alias or f"Holder-{connection_id[:8]}",
            "connected_at": time.time(),
            "proofs_requested": 0,
            "proofs_verified": 0
        }
        log_msg(f"✅ Added holder connection: {connection_id} ({self.holder_connections[connection_id]['alias']})")

    def get_holder_connections(self):
        """Get all holder connections"""
        return list(self.holder_connections.keys())

    async def handle_connections(self, payload):
        """Handle connection state changes"""
        conn_id = payload.get("connection_id")
        state = payload.get("state")
        
        log_msg(f"Connection {conn_id} state: {state}")
        
        if state == "active" and conn_id:
            try:
                # Get connection info
                connection_info = await self.admin_GET(f"/connections/{conn_id}")
                their_label = connection_info.get("their_label", "")
                alias = connection_info.get("alias", f"Holder-{conn_id[:8]}")
                
                # Add this as a holder connection (Company A only connects to holders)
                self.add_holder_connection(conn_id, alias)
                
                log_msg(f"🏢 Company A connected to holder: {conn_id} ({alias})")
                
            except Exception as e:
                # Fallback - still add the connection
                self.add_holder_connection(conn_id)
                log_msg(f"Could not get connection details, but added connection: {e}")

    async def handle_present_proof(self, payload):
        """Handle present proof webhook events"""
        presentation_exchange_id = payload.get("presentation_exchange_id")
        state = payload.get("state")
        connection_id = payload.get("connection_id")
        
        log_msg(f"📋 Proof exchange {presentation_exchange_id} state: {state}")
        
        if state == "presentation_received":
            # Proof received, automatically verify it
            log_msg("🔍 Proof received, verifying...")
            
        elif state == "verified":
            # Proof verified successfully
            presentation = payload.get("presentation", {})
            
            # Store verified proof
            self.verified_proofs[presentation_exchange_id] = {
                "connection_id": connection_id,
                "verified_at": time.time(),
                "presentation": presentation
            }
            
            # Update connection stats
            if connection_id in self.holder_connections:
                self.holder_connections[connection_id]["proofs_verified"] += 1
            
            log_msg("✅ PROOF VERIFICATION SUCCESSFUL!")
            log_msg("=" * 50)
            
            # Extract and display credential information
            if "requested_proof" in presentation:
                revealed_attrs = presentation["requested_proof"].get("revealed_attrs", {})
                log_msg("📋 Verified Credential Information:")
                for attr_name, attr_data in revealed_attrs.items():
                    log_msg(f"   {attr_name}: {attr_data.get('raw', 'N/A')}")
                
                # Check predicates
                predicates = presentation["requested_proof"].get("predicates", {})
                if predicates:
                    log_msg("🔢 Verified Predicates:")
                    for pred_name in predicates:
                        log_msg(f"   {pred_name}: ✅ SATISFIED")
            
            log_msg("=" * 50)
            
        elif state == "presentation_acked":
            log_msg("📨 Proof verification acknowledged by holder")

    def generate_university_proof_request(self, aip, cred_type, revocation, exchange_tracing, connection_id=None, connectionless=False):
        """Generate proof request for university credentials"""
        
        if aip == 10:
            # AIP 1.0 format
            # Use attributes that match the schema used by uni_reg_a and uni_admin_a
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
            
            if SELF_ATTESTED:
                req_attrs.append({"name": "self_attested_thing"})
            
            # No predicates needed for basic verification
            req_preds = []
            
            indy_proof_request = {
                "name": "Company A - University Credential Verification",
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
            
            proof_request = {
                "proof_request": indy_proof_request,
                "trace": exchange_tracing,
            }
            
            if not connectionless and connection_id:
                proof_request["connection_id"] = connection_id
                
            return proof_request
            
        elif aip == 20:
            if cred_type == CRED_FORMAT_INDY:
                # AIP 2.0 Indy format
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
                
                if SELF_ATTESTED:
                    req_attrs.append({"name": "self_attested_thing"})
                
                # No predicates needed for this verification
                req_preds = []
                
                indy_proof_request = {
                    "name": "Company A - University Credential Verification",
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
                
                proof_request = {
                    "presentation_request": {"indy": indy_proof_request},
                    "trace": exchange_tracing,
                }
                
                if not connectionless and connection_id:
                    proof_request["connection_id"] = connection_id
                    
                return proof_request
                
            elif cred_type == CRED_FORMAT_JSON_LD:
                # AIP 2.0 JSON-LD format
                proof_request = {
                    "comment": "Company A verification request for university registration json-ld",
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
                                            "fields": [
                                                {
                                                    "path": ["$.credentialSubject.givenName"],
                                                    "purpose": "We need your first name"
                                                },
                                                {
                                                    "path": ["$.credentialSubject.familyName"],
                                                    "purpose": "We need your last name"
                                                },
                                                {
                                                    "path": ["$.credentialSubject.universityName"],
                                                    "purpose": "We need your university name"
                                                },
                                                {
                                                    "path": ["$.credentialSubject.graduationYear"],
                                                    "purpose": "We need your graduation year"
                                                },
                                                {
                                                    "path": ["$.credentialSubject.cgpa"],
                                                    "purpose": "We need your CGPA"
                                                }
                                            ],
                                        },
                                    }
                                ],
                            },
                        }
                    },
                }
                
                if not connectionless and connection_id:
                    proof_request["connection_id"] = connection_id
                    
                return proof_request
                
            else:
                raise Exception(f"Error invalid credential type: {cred_type}")
        else:
            raise Exception(f"Error invalid AIP level: {aip}")

    def generate_generic_proof_request(self, aip, cred_type, exchange_tracing, connection_id=None, schema_name=None, attributes=None):
        """Generate a generic proof request for any schema"""
        
        if not schema_name:
            schema_name = "university registration schema"  # default
            
        if not attributes:
            attributes = ["student_name", "student_id"]  # default attributes
        
        if aip == 20 and cred_type == CRED_FORMAT_INDY:
            req_attrs = []
            for attr in attributes:
                req_attrs.append({
                    "name": attr,
                    "restrictions": [{"schema_name": schema_name}],
                })
            
            indy_proof_request = {
                "name": f"Company A - Generic Credential Verification ({schema_name})",
                "version": "1.0",
                "requested_attributes": {
                    f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                },
                "requested_predicates": {},
            }
            
            proof_request = {
                "presentation_request": {"indy": indy_proof_request},
                "trace": exchange_tracing,
            }
            
            if connection_id:
                proof_request["connection_id"] = connection_id
                
            return proof_request
        
        # Fallback to university request for other formats
        return self.generate_university_proof_request(aip, cred_type, False, exchange_tracing, connection_id)


async def main(args):
    extra_args = None
    if DEMO_EXTRA_AGENT_ARGS:
        extra_args = json.loads(DEMO_EXTRA_AGENT_ARGS)
        print("Got extra args:", extra_args)

    # Docker networking fix
    import os
    if os.path.exists("/.dockerenv"):
        log_msg("Detected Docker container environment")
        os.environ["RUNMODE"] = "docker"
        os.environ["DOCKERHOST"] = "172.17.0.1"
        os.environ["AGENT_ENDPOINT"] = "http://172.17.0.1:8080"  # Using port 8080 for company_a
        log_msg("Set RUNMODE=docker, DOCKERHOST=172.17.0.1, and AGENT_ENDPOINT for container networking")
    elif "ENDPOINT" in os.environ:
        # Use the endpoint passed from company_a-local.sh
        log_msg(f"Using endpoint from environment: {os.environ['ENDPOINT']}")
        # This will override any other endpoint settings
        os.environ["AGENT_ENDPOINT"] = os.environ["ENDPOINT"]
        log_msg(f"Set AGENT_ENDPOINT to {os.environ['AGENT_ENDPOINT']}")

    company_a_agent = await create_agent_with_args(
        args,
        ident="company_a",
        extra_args=extra_args,
    )

    try:
        log_status(
            "#1 Provision Company A agent and wallet - VERIFIER ONLY"
            + (
                f" (Wallet type: {company_a_agent.wallet_type})"
                if company_a_agent.wallet_type
                else ""
            )
        )

        agent = CompanyAAgent(
            "company_a.agent",
            company_a_agent.start_port,
            company_a_agent.start_port + 1,
            genesis_data=company_a_agent.genesis_txns,
            genesis_txn_list=company_a_agent.genesis_txn_list,
            no_auto=company_a_agent.no_auto,
            tails_server_base_url=company_a_agent.tails_server_base_url,
            revocation=company_a_agent.revocation,
            timing=company_a_agent.show_timing,
            multitenant=company_a_agent.multitenant,
            mediation=company_a_agent.mediation,
            wallet_type=company_a_agent.wallet_type,
            seed=None,  # Explicitly set seed to None for verifier-only agent
            aip=company_a_agent.aip,
            endorser_role=company_a_agent.endorser_role,
            anoncreds_legacy_revocation=company_a_agent.anoncreds_legacy_revocation,
            log_file=company_a_agent.log_file,
            log_config=company_a_agent.log_config,
            log_level=company_a_agent.log_level,
            reuse_connections=company_a_agent.reuse_connections,
            multi_use_invitations=company_a_agent.multi_use_invitations,
            public_did_connections=company_a_agent.public_did_connections,
            extra_args=extra_args,
        )

        # Initialize as verifier only (no schema creation needed)
        company_a_agent.public_did = False  # Verifier doesn't need public DID
        await company_a_agent.initialize(the_agent=agent)

        log_msg("🏢 Company A Agent initialized successfully as VERIFIER ONLY")
        
        # Generate invitation for holders to connect
        await company_a_agent.generate_invitation(
            display_qr=True,
            reuse_connections=company_a_agent.reuse_connections,
            multi_use_invitations=company_a_agent.multi_use_invitations,
            public_did_connections=company_a_agent.public_did_connections,
            wait=False,
        )

        log_msg("🏢 Company A ready to verify credentials from any issuer")
        
        exchange_tracing = False
        
        options = (
            "    (1) Send University Credential Proof Request\n"
            "    (2) Send Generic Proof Request\n"
            "    (2a) Send Connectionless Proof Request (requires a Mobile client)\n"
            "    (3) Send Message to Holder\n"
            "    (4) Create New Invitation\n"
            "    (5) List Connected Holders\n"
            "    (6) List Verified Proofs\n"
            "    (7) View Connection Statistics\n"
        )
        
        if company_a_agent.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (T) Toggle tracing on proof exchange\n"
        options += "    (X) Exit?\n[1/2/3/4/5/6/7/{}T/X] ".format(
            "W/" if company_a_agent.multitenant else "",
        )

        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "wW" and company_a_agent.multitenant:
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = await prompt(
                    "(Y/N) Create sub-wallet webhook target: "
                )
                if include_subwallet_webhook.lower() == "y":
                    created = await company_a_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        webhook_port=company_a_agent.agent.get_new_webhook_port(),
                        public_did=False,  # Verifier doesn't need public DID
                        mediator_agent=company_a_agent.mediator_agent,
                        endorser_agent=company_a_agent.endorser_agent,
                        taa_accept=company_a_agent.taa_accept,
                    )
                else:
                    created = await company_a_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        public_did=False,
                        mediator_agent=company_a_agent.mediator_agent,
                        endorser_agent=company_a_agent.endorser_agent,
                        cred_type=company_a_agent.cred_type,
                        taa_accept=company_a_agent.taa_accept,
                    )

            elif option in "tT":
                exchange_tracing = not exchange_tracing
                log_msg(
                    ">>> Proof Exchange Tracing is {}".format(
                        "ON" if exchange_tracing else "OFF"
                    )
                )

            elif option == "1":
                log_status("#20 Send University Credential Proof Request")
                holder_connections = agent.get_holder_connections()
                
                if not holder_connections:
                    log_msg("❌ No holder connections available. Please create invitation first (option 4).")
                    continue
                
                # Show available connections
                log_msg("Available holder connections:")
                for i, conn_id in enumerate(holder_connections, 1):
                    alias = agent.holder_connections[conn_id]["alias"]
                    log_msg(f"  {i}. {conn_id} ({alias})")
                
                if len(holder_connections) == 1:
                    selected_conn = holder_connections[0]
                else:
                    selection = await prompt(f"Select connection (1-{len(holder_connections)}): ")
                    try:
                        selected_conn = holder_connections[int(selection) - 1]
                    except (ValueError, IndexError):
                        log_msg("Invalid selection")
                        continue
                
                # Generate and send proof request
                try:
                    proof_request = agent.generate_university_proof_request(
                        company_a_agent.aip,
                        company_a_agent.cred_type,
                        company_a_agent.revocation,
                        exchange_tracing,
                        connection_id=selected_conn
                    )
                    
                    # Update connection stats
                    agent.holder_connections[selected_conn]["proofs_requested"] += 1
                    
                    if company_a_agent.aip == 10:
                        await agent.admin_POST("/present-proof/send-request", proof_request)
                    elif company_a_agent.aip == 20:
                        await agent.admin_POST("/present-proof-2.0/send-request", proof_request)
                    
                    log_msg(f"📤 University credential proof request sent to {selected_conn}")
                    
                except Exception as e:
                    log_msg(f"❌ Error sending proof request: {e}")

            elif option == "2":
                log_status("#21 Send Generic Proof Request")
                holder_connections = agent.get_holder_connections()
                
                if not holder_connections:
                    log_msg("❌ No holder connections available.")
                    continue
                
                # Show available connections
                log_msg("Available holder connections:")
                for i, conn_id in enumerate(holder_connections, 1):
                    alias = agent.holder_connections[conn_id]["alias"]
                    log_msg(f"  {i}. {conn_id} ({alias})")
                
                if len(holder_connections) == 1:
                    selected_conn = holder_connections[0]
                else:
                    selection = await prompt(f"Select connection (1-{len(holder_connections)}): ")
                    try:
                        selected_conn = holder_connections[int(selection) - 1]
                    except (ValueError, IndexError):
                        log_msg("Invalid selection")
                        continue
                
                # Get custom schema and attributes
                schema_name = await prompt("Enter schema name (or press Enter for default): ")
                if not schema_name:
                    schema_name = "university registration schema"
                
                attributes_input = await prompt("Enter attributes (comma-separated, or press Enter for default): ")
                if attributes_input:
                    attributes = [attr.strip() for attr in attributes_input.split(",")]
                else:
                    attributes = ["student_name", "university_name", "graduation_year"]
                
                try:
                    proof_request = agent.generate_generic_proof_request(
                        company_a_agent.aip,
                        company_a_agent.cred_type,
                        exchange_tracing,
                        connection_id=selected_conn,
                        schema_name=schema_name,
                        attributes=attributes
                    )
                    
                    agent.holder_connections[selected_conn]["proofs_requested"] += 1
                    
                    if company_a_agent.aip == 20:
                        await agent.admin_POST("/present-proof-2.0/send-request", proof_request)
                    else:
                        await agent.admin_POST("/present-proof/send-request", proof_request)
                    
                    log_msg(f"📤 Generic proof request sent to {selected_conn}")
                    
                except Exception as e:
                    log_msg(f"❌ Error sending proof request: {e}")

            elif option == "2a":
                log_status("#22 Send Connectionless Proof Request")
                
                try:
                    proof_request = agent.generate_university_proof_request(
                        company_a_agent.aip,
                        company_a_agent.cred_type,
                        company_a_agent.revocation,
                        exchange_tracing,
                        connectionless=True
                    )
                    
                    if company_a_agent.aip == 10:
                        proof_req_response = await agent.admin_POST(
                            "/present-proof/create-request", proof_request
                        )
                        pres_req_id = proof_req_response["presentation_exchange_id"]
                    else:
                        proof_req_response = await agent.admin_POST(
                            "/present-proof-2.0/create-request", proof_request
                        )
                        pres_req_id = proof_req_response["pres_ex_id"]
                    
                    url = (
                        os.getenv("WEBHOOK_TARGET")
                        or (
                            "http://"
                            + os.getenv("DOCKERHOST", "localhost").replace(
                                "{PORT}", str(agent.admin_port + 1)
                            )
                            + "/webhooks"
                        )
                    ) + f"/pres_req/{pres_req_id}/"
                    
                    log_msg(f"Connectionless proof request URL: {url}")
                    qr = QRCode(border=1)
                    qr.add_data(url)
                    log_msg("Scan the following QR code to respond to the proof request:")
                    qr.print_ascii(invert=True)
                    
                except Exception as e:
                    log_msg(f"❌ Error creating connectionless proof request: {e}")

            elif option == "3":
                log_status("#23 Send Message to Holder")
                holder_connections = agent.get_holder_connections()
                
                if not holder_connections:
                    log_msg("❌ No holder connections available.")
                    continue
                
                log_msg("Available holder connections:")
                for i, conn_id in enumerate(holder_connections, 1):
                    alias = agent.holder_connections[conn_id]["alias"]
                    log_msg(f"  {i}. {conn_id} ({alias})")
                
                if len(holder_connections) == 1:
                    selected_conn = holder_connections[0]
                else:
                    selection = await prompt(f"Select connection (1-{len(holder_connections)}): ")
                    try:
                        selected_conn = holder_connections[int(selection) - 1]
                    except (ValueError, IndexError):
                        log_msg("Invalid selection")
                        continue
                
                msg = await prompt("Enter message: ")
                try:
                    await agent.admin_POST(
                        f"/connections/{selected_conn}/send-message",
                        {"content": msg},
                    )
                    log_msg(f"📤 Message sent to {selected_conn}")
                except Exception as e:
                    log_msg(f"❌ Error sending message: {e}")

            elif option == "4":
                log_msg("🏢 Creating new invitation for holders to connect to Company A")
                await company_a_agent.generate_invitation(
                    display_qr=True,
                    reuse_connections=company_a_agent.reuse_connections,
                    multi_use_invitations=company_a_agent.multi_use_invitations,
                    public_did_connections=company_a_agent.public_did_connections,
                    wait=True,
                )

            elif option == "5":
                log_status("#24 List Connected Holders")
                if not agent.holder_connections:
                    log_msg("❌ No holder connections.")
                else:
                    log_msg("🏢 Company A - Connected Holders:")
                    for conn_id, info in agent.holder_connections.items():
                        connected_time = datetime.datetime.fromtimestamp(info["connected_at"])
                        log_msg(f"  • {conn_id} ({info['alias']})")
                        log_msg(f"    Connected: {connected_time}")
                        log_msg(f"    Proofs Requested: {info['proofs_requested']}")
                        log_msg(f"    Proofs Verified: {info['proofs_verified']}")

            elif option == "6":
                log_status("#25 List Verified Proofs")
                if not agent.verified_proofs:
                    log_msg("❌ No verified proofs.")
                else:
                    log_msg("🏢 Company A - Verified Proofs:")
                    for proof_id, info in agent.verified_proofs.items():
                        verified_time = datetime.datetime.fromtimestamp(info["verified_at"])
                        log_msg(f"  • Proof ID: {proof_id}")
                        log_msg(f"    Connection: {info['connection_id']}")
                        log_msg(f"    Verified: {verified_time}")
                        
                        # Show credential data if available
                        presentation = info.get("presentation", {})
                        if "requested_proof" in presentation:
                            revealed_attrs = presentation["requested_proof"].get("revealed_attrs", {})
                            if revealed_attrs:
                                log_msg("    Credential Data:")
                                for attr_name, attr_data in revealed_attrs.items():
                                    log_msg(f"      {attr_name}: {attr_data.get('raw', 'N/A')}")

            elif option == "7":
                log_status("#26 View Connection Statistics")
                if not agent.holder_connections:
                    log_msg("❌ No connections to show statistics for.")
                else:
                    total_connections = len(agent.holder_connections)
                    total_proofs_requested = sum(info["proofs_requested"] for info in agent.holder_connections.values())
                    total_proofs_verified = sum(info["proofs_verified"] for info in agent.holder_connections.values())
                    
                    log_msg("🏢 Company A - Statistics:")
                    log_msg(f"  Total Holder Connections: {total_connections}")
                    log_msg(f"  Total Proof Requests Sent: {total_proofs_requested}")
                    log_msg(f"  Total Proofs Verified: {total_proofs_verified}")
                    log_msg(f"  Verification Success Rate: {(total_proofs_verified/total_proofs_requested*100 if total_proofs_requested > 0 else 0):.1f}%")

        if company_a_agent.show_timing:
            timing = await agent.fetch_timing()
            if timing:
                for line in agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await company_a_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="company_a", port=8080)
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
                "CompanyA remote debugging to "
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