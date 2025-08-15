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
DEMO_EXTRA_AGENT_ARGS = os.getenv("DEMO_EXTRA_AGENT_ARGS")

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class UniAdminAgent(AriesAgent):
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
            prefix="UniAdmin",
            no_auto=no_auto,
            endorser_role=endorser_role,
            revocation=revocation,
            anoncreds_legacy_revocation=anoncreds_legacy_revocation,
            log_file=log_file,
            log_config=log_config,
            log_level=log_level,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.registrar_connection_id = None
        self.pending_approvals = {}  # Store pending credential approvals
        
    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()
        
    def register_webhook_handler(self, handler):
        """
        Register a webhook handler function to process incoming webhooks.
        
        Args:
            handler (callable): The async function to call when a webhook is received
        """
        # This is just a stub method since the actual webhook handling is done by the parent class
        log_msg("Webhook handler registered successfully")
        
    def add_message_handler(self, message_type, handler):
        """
        Register a handler for messages with the specified type.
        
        Args:
            message_type (str): The message type to listen for
            handler (callable): The async function to call when a message of this type arrives
        """
        log_msg(f"Message handler registered for {message_type if message_type else 'all messages'}")

    def generate_approval_response(self, approval_id, approved, comments=""):
        """Generate approval response message to send back to registrar"""
        # Keep it simple with just the essential data
        # The send_approval_response method will use this directly
        response = {
            "type": "credential_approval_response",
            "approval_id": approval_id,
            "approved": approved,
            "comments": comments,
            "timestamp": str(int(time.time())),
            "admin_id": "ADMIN001"
        }
        return response

    async def handle_webhook(self, topic, payload, headers=None):
        """
        Process incoming webhook notifications from ACA-Py
        """
        log_msg(f"Received webhook: {topic}")
        log_msg(f"Payload: {json.dumps(payload, indent=2)}")
        
        if topic == "basicmessages":
            await self.handle_basicmessage(payload)
        elif topic == "connections":
            await self.handle_connections(payload)
    
    async def handle_basicmessage(self, payload):
        """Handle incoming basic message webhook"""
        message_id = payload.get("message_id", "")
        content = payload.get("content", "")
        connection_id = payload.get("connection_id", "")
        
        # Try to parse content as JSON
        if content:
            try:
                content_json = json.loads(content)
                if isinstance(content_json, dict) and content_json.get("type") == "credential_approval_request":
                    log_msg("Received credential approval request via webhook")
                    await self.handle_approval_request(payload)
            except json.JSONDecodeError:
                log_msg("Basic message content is not JSON")
    
    async def handle_connections(self, payload):
        """Handle connection state changes"""
        conn_id = payload.get("connection_id")
        if payload.get("state") == "active" and conn_id:
            log_msg(f"Connection {conn_id} is now active")
            # If this is from the registrar, store it
            if not self.registrar_connection_id:
                self.registrar_connection_id = conn_id
                log_msg(f"Set registrar connection ID to: {self.registrar_connection_id}")
    
    async def handle_approval_request(self, message_data):
        """Handle incoming credential approval requests from registrar"""
        try:
            log_msg(f"Received message: {json.dumps(message_data, indent=2)}")
            
            # Extract content - handle various message formats
            content = None
            
            # Check for different possible content locations
            if "content" in message_data:
                content = message_data["content"]
                
            if not content:
                log_msg("No content found in message")
                return
                
            # Parse the content if it's a string
            if isinstance(content, str):
                try:
                    content = json.loads(content)
                except json.JSONDecodeError:
                    log_msg(f"Could not parse message content as JSON: {content}")
                    # It might be a simple text message, not JSON
                    content = {"text": content}
            
            # Look for approval request data
            request_data = None
            
            # Check various paths where the request data might be found
            if isinstance(content, dict):
                if "type" in content and content.get("type") == "credential_approval_request":
                    request_data = content
                elif "student_data" in content:
                    request_data = content
            
            if not request_data:
                log_msg("No credential request data found in message")
                return
                
            # Determine if this is an approval request
            is_approval_request = False
            if "type" in request_data and request_data["type"] == "credential_approval_request":
                is_approval_request = True
            elif "student_data" in request_data:
                is_approval_request = True
                
            if is_approval_request:
                # Extract the approval ID
                approval_id = request_data.get("approval_id")
                if not approval_id and "@id" in message_data:
                    approval_id = message_data["@id"]
                elif not approval_id:
                    approval_id = str(uuid.uuid4())  # Generate one if missing
                
                # Extract student data
                student_data = request_data.get("student_data", {})
                
                # Determine connection ID
                connection_id = None
                if "connection_id" in message_data:
                    connection_id = message_data["connection_id"]
                elif hasattr(self, "registrar_connection_id") and self.registrar_connection_id:
                    connection_id = self.registrar_connection_id
                elif "connection_id" in request_data:
                    connection_id = request_data["connection_id"]
                    
                if not connection_id and self.connection_id:
                    connection_id = self.connection_id
                
                # Store the pending approval
                self.pending_approvals[approval_id] = {
                    "student_data": student_data,
                    "request_time": time.time(),
                    "registrar_connection_id": connection_id
                }
                
                log_msg(f"\n=== CREDENTIAL APPROVAL REQUEST RECEIVED ===")
                log_msg(f"Approval ID: {approval_id}")
                log_msg(f"From connection: {connection_id}")
                log_msg(f"Student Name: {student_data.get('student_name', 'N/A')}")
                log_msg(f"Student ID: {student_data.get('student_id', 'N/A')}")
                log_msg(f"Program: {student_data.get('program', 'N/A')}")
                log_msg(f"Year: {student_data.get('year', 'N/A')}")
                log_msg(f"GPA: {student_data.get('gpa', 'N/A')}")
                log_msg("=== Use option '1' to approve or '2' to reject ===\n")
            else:
                log_msg(f"Message is not a credential approval request")
                
        except Exception as e:
            log_msg(f"Error handling approval request: {e}")
            import traceback
            traceback.print_exc()

    async def send_approval_response(self, approval_id, approved, comments=""):
        """Send approval response back to registrar"""
        if approval_id not in self.pending_approvals:
            log_msg(f"No pending approval found for ID: {approval_id}")
            return
            
        approval_data = self.pending_approvals[approval_id]
        registrar_connection_id = approval_data["registrar_connection_id"]
        
        if not registrar_connection_id:
            log_msg("No registrar connection ID found. Using default connection.")
            registrar_connection_id = self.connection_id
            
        if not registrar_connection_id:
            log_msg("No connection ID available to send message. Cannot send approval response.")
            return
            
        # Check if the connection is active before sending
        log_msg(f"Checking connection status for {registrar_connection_id}...")
        try:
            conn = await self.admin_GET(f"/connections/{registrar_connection_id}")
            if conn["state"] != "active":
                log_msg(f"Connection {registrar_connection_id} is not active (state: {conn['state']})")
                log_msg("Waiting for connection to become active...")
                
                # Wait for the connection to become active
                for _ in range(10):  # Try for up to 10 seconds
                    await asyncio.sleep(1)
                    conn = await self.admin_GET(f"/connections/{registrar_connection_id}")
                    log_msg(f"Connection state: {conn['state']}")
                    if conn["state"] == "active":
                        log_msg("Connection is now active!")
                        break
                else:
                    log_msg("Connection did not become active. Cannot send message.")
                    return
        except Exception as e:
            log_msg(f"Error checking connection status: {e}")
            
        # Generate the response
        response = self.generate_approval_response(approval_id, approved, comments)
        log_msg(f"Sending approval response: {json.dumps(response, indent=2)}")
        
        # Simplify the message to ensure compatibility
        simplified_response = {
            "type": "credential_approval_response",
            "approval_id": approval_id,
            "approved": approved,
            "comments": comments,
            "timestamp": str(int(time.time())),
            "admin_id": "ADMIN001"
        }
        
        # Use only the standard endpoint that should work in all versions
        endpoint = f"/connections/{registrar_connection_id}/send-message"
        payload = {"content": json.dumps(simplified_response)}
        
        try:
            log_msg(f"Sending response using endpoint: {endpoint}")
            await self.admin_POST(endpoint, payload)
            log_msg(f"Successfully sent response")
            success = True
        except Exception as e:
            log_msg(f"Failed to send response: {str(e)}")
            success = False
                
        if success:
            # Remove from pending approvals
            del self.pending_approvals[approval_id]
            
            status = "APPROVED" if approved else "REJECTED"
            log_msg(f"Approval response sent - {status} for approval ID: {approval_id}")
        else:
            log_msg(f"Error sending approval response: All endpoints failed")


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
        # Set the correct endpoint to eliminate localhost errors
        os.environ["AGENT_ENDPOINT"] = "http://172.17.0.1:8070"
        log_msg("Set RUNMODE=docker, DOCKERHOST=172.17.0.1, and AGENT_ENDPOINT for container networking")
        
    # Check for endpoint from environment variable (set by start script)
    endpoint = os.environ.get('ENDPOINT', 'http://172.17.0.1:8070')
    log_msg(f"Using endpoint: {endpoint}")
    
    if extra_args is None:
        extra_args = []
        
    # Add endpoint to extra args
    extra_args.extend([
        "--endpoint", endpoint
    ])

    uni_admin_a_agent = await create_agent_with_args(
        args,
        ident="uni_admin_a",
        extra_args=extra_args,
    )

    try:
        log_status(
            "#1 Provision an admin agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {uni_admin_a_agent.wallet_type})"
                if uni_admin_a_agent.wallet_type
                else ""
            )
        )
        
        agent = UniAdminAgent(
            "uni_admin_a.agent",
            uni_admin_a_agent.start_port,
            uni_admin_a_agent.start_port + 1,
            genesis_data=uni_admin_a_agent.genesis_txns,
            genesis_txn_list=uni_admin_a_agent.genesis_txn_list,
            no_auto=uni_admin_a_agent.no_auto,
            tails_server_base_url=uni_admin_a_agent.tails_server_base_url,
            revocation=uni_admin_a_agent.revocation,
            timing=uni_admin_a_agent.show_timing,
            multitenant=uni_admin_a_agent.multitenant,
            mediation=uni_admin_a_agent.mediation,
            wallet_type=uni_admin_a_agent.wallet_type,
            seed=uni_admin_a_agent.seed,
            aip=uni_admin_a_agent.aip,
            endorser_role=uni_admin_a_agent.endorser_role,
            anoncreds_legacy_revocation=uni_admin_a_agent.anoncreds_legacy_revocation,
            log_file=uni_admin_a_agent.log_file,
            log_config=uni_admin_a_agent.log_config,
            log_level=uni_admin_a_agent.log_level,
            reuse_connections=uni_admin_a_agent.reuse_connections,
            multi_use_invitations=uni_admin_a_agent.multi_use_invitations,
            public_did_connections=uni_admin_a_agent.public_did_connections,
            extra_args=extra_args,
        )

        # Debug: Show exact port configuration
        log_msg(f"🔧 Admin Agent Port Configuration:")
        log_msg(f"   Start Port: {uni_admin_a_agent.start_port}")
        log_msg(f"   HTTP Port: {uni_admin_a_agent.start_port} (agent communication)")
        log_msg(f"   Admin API Port: {uni_admin_a_agent.start_port + 1}")
        log_msg(f"   Webhook Port: {uni_admin_a_agent.start_port + 2}")

        # Initialize the same way as registrar agent
        if uni_admin_a_agent.cred_type == CRED_FORMAT_INDY:
            uni_admin_a_agent.public_did = True
            await uni_admin_a_agent.initialize(the_agent=agent)
            log_msg("Admin agent initialized successfully")
        elif uni_admin_a_agent.cred_type == CRED_FORMAT_JSON_LD:
            uni_admin_a_agent.public_did = True
            await uni_admin_a_agent.initialize(the_agent=agent)
            log_msg("Admin agent initialized successfully")
        else:
            raise Exception("Invalid credential type:" + str(uni_admin_a_agent.cred_type))

        # Generate invitation for registrar to connect (similar to uni_reg_a pattern)
        log_msg("Generating invitation for registrar connection...")
        try:
            invitation = await uni_admin_a_agent.generate_invitation(
                display_qr=False,  # We'll handle display manually
                reuse_connections=uni_admin_a_agent.reuse_connections,
                multi_use_invitations=uni_admin_a_agent.multi_use_invitations,
                public_did_connections=uni_admin_a_agent.public_did_connections,
                wait=False,
            )
            
            # Generate clean, single-line JSON without extra whitespace
            clean_invitation = json.dumps(invitation["invitation"], separators=(',', ':'))
            
            # Display in a way that's easy to copy
            log_msg("\n" + "="*60)
            log_msg("COPY THE FULL LINE BELOW FOR REGISTRAR AGENT:")
            log_msg("="*60)
            log_msg(clean_invitation)
            log_msg("="*60)
            log_msg("END OF INVITATION TO COPY")
            log_msg("="*60 + "\n")
            
            # Also show the QR code for mobile connections
            qr = QRCode(border=1)
            qr.add_data(invitation["invitation_url"])
            log_msg("QR Code for mobile wallets:")
            qr.print_ascii(invert=True)
            
            log_msg("Admin agent ready to receive connection from registrar")
                
        except Exception as e:
            log_msg(f"Error generating invitation: {str(e)}")
        
        # The agent is ready - webhooks will handle incoming messages automatically
        log_msg("Agent ready to process credential approval requests from registrar via webhooks")

        options = (
            "    (1) Approve Pending Credential Request\n"
            "    (2) Reject Pending Credential Request\n"
            "    (3) List Pending Approval Requests\n"
            "    (4) Send Message to Registrar\n"
            "    (5) Create New Invitation\n"
            "    (X) Exit?\n[1/2/3/4/5/X] "
        )

        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option == "1":
                # Approve credential request
                if not agent.pending_approvals:
                    log_msg("No pending approval requests.")
                    continue
                
                log_msg("\nPending Approval Requests:")
                for approval_id, data in agent.pending_approvals.items():
                    student_data = data["student_data"]
                    log_msg(f"ID: {approval_id}")
                    log_msg(f"  Student: {student_data.get('student_name', 'N/A')}")
                    log_msg(f"  Program: {student_data.get('program', 'N/A')}")
                    log_msg(f"  Student ID: {student_data.get('student_id', 'N/A')}")
                    log_msg("")
                
                approval_id = await prompt("Enter approval ID to approve: ")
                comments = await prompt("Enter approval comments (optional): ")
                
                await agent.send_approval_response(approval_id, True, comments)

            elif option == "2":
                # Reject credential request
                if not agent.pending_approvals:
                    log_msg("No pending approval requests.")
                    continue
                
                log_msg("\nPending Approval Requests:")
                for approval_id, data in agent.pending_approvals.items():
                    student_data = data["student_data"]
                    log_msg(f"ID: {approval_id}")
                    log_msg(f"  Student: {student_data.get('student_name', 'N/A')}")
                    log_msg(f"  Program: {student_data.get('program', 'N/A')}")
                    log_msg(f"  Student ID: {student_data.get('student_id', 'N/A')}")
                    log_msg("")
                
                approval_id = await prompt("Enter approval ID to reject: ")
                comments = await prompt("Enter rejection reason: ")
                
                await agent.send_approval_response(approval_id, False, comments)

            elif option == "3":
                # List pending requests
                if not agent.pending_approvals:
                    log_msg("No pending approval requests.")
                else:
                    log_msg("\n=== PENDING APPROVAL REQUESTS ===")
                    for approval_id, data in agent.pending_approvals.items():
                        student_data = data["student_data"]
                        request_time = datetime.datetime.fromtimestamp(data["request_time"])
                        log_msg(f"\nApproval ID: {approval_id}")
                        log_msg(f"Request Time: {request_time}")
                        log_msg(f"Student Name: {student_data.get('student_name', 'N/A')}")
                        log_msg(f"Student ID: {student_data.get('student_id', 'N/A')}")
                        log_msg(f"Program: {student_data.get('program', 'N/A')}")
                        log_msg(f"Year: {student_data.get('year', 'N/A')}")
                        log_msg(f"GPA: {student_data.get('gpa', 'N/A')}")

            elif option == "4":
                # Send message to registrar
                if not agent.connection_id:
                    log_msg("No connection to registrar established.")
                    continue
                    
                msg = await prompt("Enter message to registrar: ")
                # Use only the standard endpoint that should work in all versions
                endpoint = f"/connections/{agent.connection_id}/send-message"
                payload = {"content": msg}
                
                try:
                    log_msg(f"Sending message using endpoint: {endpoint}")
                    await agent.admin_POST(endpoint, payload)
                    log_msg(f"Successfully sent message")
                except Exception as e:
                    log_msg(f"Failed to send message: {str(e)}")

            elif option == "5":
                # Create new invitation
                log_msg("Creating a new invitation for registrar connection")
                invitation = await uni_admin_a_agent.generate_invitation(
                    display_qr=False,  # We'll handle QR display manually
                    reuse_connections=uni_admin_a_agent.reuse_connections,
                    multi_use_invitations=uni_admin_a_agent.multi_use_invitations,
                    public_did_connections=uni_admin_a_agent.public_did_connections,
                    wait=False,
                )
                
                # Generate clean, single-line JSON without extra whitespace
                clean_invitation = json.dumps(invitation["invitation"], separators=(',', ':'))
                
                # Display in a way that's easy to copy
                log_msg("\n" + "="*50)
                log_msg("COPY THE FULL LINE BELOW FOR REGISTRAR:")
                log_msg("="*50)
                log_msg(clean_invitation)
                log_msg("="*50)
                log_msg("END OF INVITATION TO COPY")
                log_msg("="*50 + "\n")
                
                # Also show the QR code for mobile connections
                qr = QRCode(border=1)
                qr.add_data(invitation["invitation_url"])
                log_msg("QR Code for mobile wallets:")
                qr.print_ascii(invert=True)

        if uni_admin_a_agent.show_timing:
            timing = await uni_admin_a_agent.agent.fetch_timing()
            if timing:
                for line in uni_admin_a_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await uni_admin_a_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="uni_admin_a", port=8070)
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
                "UniAdmin remote debugging to "
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