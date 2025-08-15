#!/usr/bin/env python3
import asyncio
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
logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)

class UniAdminAAgent(AriesAgent):
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
            prefix="UniAdminA",
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
        self._connection_ready = asyncio.Future()
        self.cred_state = {}
        self.approval_queue = {}
        self.registrar_connection_id = None
        
        # Debug: Print initialization
        log_msg("🔍 DEBUG: UniAdminAAgent initialized with empty approval_queue")

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
        
        if state in ("active", "response"):
            log_msg(f"🔗 Connection established: {connection_id}")
            if not self.connection_id:
                self.connection_id = connection_id
            
            # Mark connection as ready
            if not self._connection_ready.done():
                self._connection_ready.set_result(True)

    async def handle_events(self, event):
        log_msg(f"🔍 DEBUG: Received event - Topic: {event['topic']}")
        
        if event["topic"] == "connections":
            await self.handle_connections(event["payload"])
        elif event["topic"] == "basicmessages":
            msg = event["payload"]
            connection_id = msg["connection_id"]
            content = msg["content"]
            
            log_msg(f"🔍 DEBUG: Basic message from {connection_id}")
            log_msg(f"🔍 DEBUG: Message content: {content}")
            
            try:
                data = json.loads(content)
                log_msg(f"🔍 DEBUG: Parsed JSON successfully: {data}")
                
                if data.get("type") == "approval_request":
                    log_msg("🔍 DEBUG: Found approval_request type - calling handler")
                    await self.handle_approval_request(data, connection_id)
                else:
                    log_msg(f"🔍 DEBUG: Message type '{data.get('type')}' is not approval_request")
                    
            except json.JSONDecodeError as e:
                log_msg(f"🔍 DEBUG: JSON decode failed: {str(e)}")
                log_msg(f"🔍 DEBUG: Raw content was: {repr(content)}")
        else:
            log_msg(f"🔍 DEBUG: Unhandled event topic: {event['topic']}")

    async def handle_approval_request(self, data, connection_id):
        log_msg("🔍 DEBUG: handle_approval_request called")
        log_msg(f"🔍 DEBUG: Data received: {data}")
        log_msg(f"🔍 DEBUG: Connection ID: {connection_id}")
        
        cred_ex_id = data["cred_ex_id"]
        student_name = data["student_name"]
        api_version = data.get("api_version", "v1")
        
        log_msg(f"🔍 DEBUG: Extracted - cred_ex_id: {cred_ex_id}, student: {student_name}, api: {api_version}")
        log_msg(f"🔍 DEBUG: Current approval_queue before adding: {list(self.approval_queue.keys())}")
        
        self.approval_queue[cred_ex_id] = {
            "student_name": student_name,
            "connection_id": connection_id,
            "status": "pending",
            "api_version": api_version
        }
        
        log_msg(f"📥 Approval request received for student: {student_name}")
        log_msg(f"🔑 Credential exchange ID: {cred_ex_id}")
        log_msg(f"📱 API version: {api_version}")
        log_msg(f"✅ Request added to approval queue. Total requests: {len(self.approval_queue)}")
        
        # Debug: Print the current approval queue
        log_msg("🔍 DEBUG: Current approval_queue contents:")
        for k, v in self.approval_queue.items():
            log_msg(f"  {k}: {v}")

    async def approve_credential(self, cred_ex_id):
        if cred_ex_id not in self.approval_queue:
            log_msg("❌ Invalid credential exchange ID")
            return
            
        request = self.approval_queue[cred_ex_id]
        connection_id = request["connection_id"]
        api_version = request.get("api_version", "v1")
        
        await self.admin_POST(
            f"/connections/{connection_id}/send-message",
            {
                "content": json.dumps({
                    "type": "approval_response",
                    "cred_ex_id": cred_ex_id,
                    "approved": True,
                    "api_version": api_version
                })
            }
        )
        
        self.approval_queue[cred_ex_id]["status"] = "approved"
        log_msg(f"✅ Approved credential for: {request['student_name']}")

    async def deny_credential(self, cred_ex_id, reason="Denied by admin"):
        if cred_ex_id not in self.approval_queue:
            log_msg("❌ Invalid credential exchange ID")
            return
            
        request = self.approval_queue[cred_ex_id]
        connection_id = request["connection_id"]
        api_version = request.get("api_version", "v1")
        
        await self.admin_POST(
            f"/connections/{connection_id}/send-message",
            {
                "content": json.dumps({
                    "type": "approval_response",
                    "cred_ex_id": cred_ex_id,
                    "approved": False,
                    "reason": reason,
                    "api_version": api_version
                })
            }
        )
        
        self.approval_queue[cred_ex_id]["status"] = "denied"
        log_msg(f"❌ Denied credential for: {request['student_name']}")
        log_msg(f"   Reason: {reason}")

async def main(args):
    extra_args = None
    if os.getenv("DEMO_EXTRA_AGENT_ARGS"):
        extra_args = json.loads(os.getenv("DEMO_EXTRA_AGENT_ARGS"))
    
    uni_admin_a_agent = await create_agent_with_args(
        args,
        ident="uni_admin_a",
        extra_args=extra_args,
    )
    
    try:
        log_status("#1 Provision an agent and wallet")
        agent = UniAdminAAgent(
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
            extra_args=extra_args,
        )
        
        await uni_admin_a_agent.initialize(the_agent=agent)
        
        log_status("#2 Generate invitation for University Registrar")
        
        # Try both out-of-band and legacy invitation methods
        invitation = None
        try:
            # First try out-of-band invitation (newer method)
            invitation = await uni_admin_a_agent.generate_invitation(
                display_qr=True,
                reuse_connections=uni_admin_a_agent.reuse_connections,
                multi_use_invitations=uni_admin_a_agent.multi_use_invitations,
                wait=False,  # Don't wait for connection here
            )
            log_msg("📤 Generated out-of-band invitation")
            
        except Exception as e:
            log_msg(f"⚠️ Out-of-band invitation failed, trying legacy method: {str(e)}")
            try:
                # Fallback to legacy connections
                response = await agent.admin_POST("/connections/create-invitation")
                invitation = response["invitation"]
                log_msg("📤 Generated legacy invitation")
            except Exception as e2:
                log_msg(f"❌ Both invitation methods failed: {str(e2)}")
                return
        
        if invitation:
            # Generate clean, single-line JSON without extra whitespace
            clean_invitation = json.dumps(invitation, separators=(',', ':'))
            
            # Display in a way that's easy to copy
            log_msg("\n" + "="*50)
            log_msg("COPY THE FULL LINE BELOW FOR UNI_REG_A:")
            log_msg("="*50)
            log_msg(clean_invitation)
            log_msg("="*50)
        
        # Wait for connection to be established with better timeout handling
        log_msg("⏳ Waiting for University Registrar to connect...")
        
        try:
            await asyncio.wait_for(agent._connection_ready, timeout=300.0)  # 5 minute timeout
            log_msg("✅ University Registrar connected successfully!")
        except asyncio.TimeoutError:
            log_msg("⏰ Timeout waiting for connection.")
            log_msg("💡 You can still proceed - the registrar might connect later.")
        except Exception as e:
            log_msg(f"⚠️ Connection error: {str(e)}")
            log_msg("💡 You can still proceed and try to reconnect later.")
        
        options = (
            "    (1) List pending approvals\n"
            "    (2) Approve credential\n"
            "    (3) Deny credential\n"
            "    (4) Send Message\n"
            "    (5) Create New Invitation\n"
            "    (6) Show Connection Status\n"
            "    (X) Exit?\n[1/2/3/4/5/6/X] "
        )
        
        async for option in prompt_loop(options):
            if option is None or option in "xX":
                break
                
            option = option.strip()
            
            if option == "1":
                if not agent.approval_queue:
                    log_msg("📭 No pending approvals")
                    continue
                
                log_msg("📋 Pending approval requests:")
                for cred_ex_id, details in agent.approval_queue.items():
                    status_icon = "⏳" if details["status"] == "pending" else "✅" if details["status"] == "approved" else "❌"
                    log_msg(f"{status_icon} {cred_ex_id}: {details['student_name']} ({details['status']})")
            
            elif option == "2":
                if not agent.approval_queue:
                    log_msg("📭 No approval requests available")
                    continue
                
                # Show pending requests
                pending_requests = {k: v for k, v in agent.approval_queue.items() if v["status"] == "pending"}
                if not pending_requests:
                    log_msg("📭 No pending approval requests")
                    continue
                
                log_msg("📋 Pending requests:")
                for cred_ex_id, details in pending_requests.items():
                    log_msg(f"  🆔 {cred_ex_id}: {details['student_name']}")
                
                cred_ex_id = await prompt("Enter credential exchange ID to approve: ")
                await agent.approve_credential(cred_ex_id)
            
            elif option == "3":
                if not agent.approval_queue:
                    log_msg("📭 No approval requests available")
                    continue
                
                # Show pending requests
                pending_requests = {k: v for k, v in agent.approval_queue.items() if v["status"] == "pending"}
                if not pending_requests:
                    log_msg("📭 No pending approval requests")
                    continue
                
                log_msg("📋 Pending requests:")
                for cred_ex_id, details in pending_requests.items():
                    log_msg(f"  🆔 {cred_ex_id}: {details['student_name']}")
                
                cred_ex_id = await prompt("Enter credential exchange ID to deny: ")
                reason = await prompt("Enter reason for denial (optional): ")
                if not reason.strip():
                    reason = "Denied by admin"
                await agent.deny_credential(cred_ex_id, reason)
            
            elif option == "4":
                if not agent.connection_id:
                    log_msg("❌ No active connection")
                    continue
                    
                msg = await prompt("Enter message: ")
                await agent.admin_POST(
                    f"/connections/{agent.connection_id}/send-message",
                    {"content": msg},
                )
                log_msg("📤 Message sent")
            
            elif option == "5":
                log_msg("🔄 Creating new invitation...")
                invitation = await uni_admin_a_agent.generate_invitation(
                    display_qr=True,
                    reuse_connections=uni_admin_a_agent.reuse_connections,
                    multi_use_invitations=uni_admin_a_agent.multi_use_invitations,
                    wait=False,
                )
                
                # Generate a clean, single-line JSON string
                clean_invitation = json.dumps(invitation, separators=(',', ':'))
                
                log_msg("\n" + "="*50)
                log_msg("COPY THE FULL LINE BELOW FOR UNI_REG_A:")
                log_msg("="*50)
                log_msg(clean_invitation)
                log_msg("="*50)
            
            elif option == "6":
                if agent.connection_id:
                    try:
                        connection = await agent.admin_GET(f"/connections/{agent.connection_id}")
                        log_msg(f"🔗 Connection ID: {agent.connection_id}")
                        log_msg(f"📊 Connection state: {connection['state']}")
                        log_msg(f"🏷️  Their label: {connection.get('their_label', 'Unknown')}")
                    except Exception as e:
                        log_msg(f"❌ Error getting connection details: {str(e)}")
                else:
                    log_msg("❌ No active connection")
                
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
    
    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)
