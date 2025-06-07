import asyncio
import sys

if sys.platform == "linux" or sys.platform == "linux2":
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
import switch
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score
from tensorflow.keras.models import load_model
import requests
from web3 import Web3

import socket, struct


class SmartDDoSDefenseController(switch.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SmartDDoSDefenseController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        
        start = datetime.now()
        
        self.flow_training()

        end = datetime.now()
        print("Training time: ", (end-start))
        
        self.deep_model = load_model('model.h5')
        self.web3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))
        self.contract = self.connect_to_contract()
        self.api_key = "6804f254155ecb6756d5cb852945d17a7febd378e67604bc5855b073868e8803a69d2261df9ef087"
        
        self.syn_attack_counter = {}

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()

        file0 = open("PredictFlowStatsfile.csv","w")
        file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
        body = ev.msg.body
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
            (flow.match['eth_type'],flow.match['ipv4_src'],flow.match['ipv4_dst'],flow.match['ip_proto'])):
        
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']
            
            if stat.match['ip_proto'] == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']
                
            elif stat.match['ip_proto'] == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']

            elif stat.match['ip_proto'] == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)
          
            try:
                packet_count_per_second = stat.packet_count/stat.duration_sec
                packet_count_per_nsecond = stat.packet_count/stat.duration_nsec
            except:
                packet_count_per_second = 0
                packet_count_per_nsecond = 0
                
            try:
                byte_count_per_second = stat.byte_count/stat.duration_sec
                byte_count_per_nsecond = stat.byte_count/stat.duration_nsec
            except:
                byte_count_per_second = 0
                byte_count_per_nsecond = 0
                
            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src,ip_dst, tp_dst,
                        stat.match['ip_proto'],icmp_code,icmp_type,
                        stat.duration_sec, stat.duration_nsec,
                        stat.idle_timeout, stat.hard_timeout,
                        stat.flags, stat.packet_count,stat.byte_count,
                        packet_count_per_second,packet_count_per_nsecond,
                        byte_count_per_second,byte_count_per_nsecond))
            
        file0.close()

    def flow_training(self):
        self.logger.info("Flow Training ...")
        flow_dataset = pd.read_csv('dataset.csv')
        flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
        flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
        flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

        X = flow_dataset.iloc[:, :-1].values.astype('float64')
        y = flow_dataset.iloc[:, -1].values
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=0)

        clf = DecisionTreeClassifier(criterion='entropy', random_state=0)
        self.flow_model = clf.fit(X_train, y_train)
    
        y_flow_pred = self.flow_model.predict(X_test)

        self.logger.info("------------------------------------------------------------------------------")
        self.logger.info("confusion matrix")
        cm = confusion_matrix(y_test, y_flow_pred)
        self.logger.info(cm)

        acc = accuracy_score(y_test, y_flow_pred)
        self.logger.info("succes accuracy = {0:.2f} %".format(acc*100))
        fail = 1.0 - acc
        self.logger.info("fail accuracy = {0:.2f} %".format(fail*100))
        self.logger.info("------------------------------------------------------------------------------")


    def flow_predict(self):
        try:
            df = pd.read_csv('PredictFlowStatsfile.csv')
            def ip_str_to_int(ip_str):
                try:
                    return struct.unpack("!I", socket.inet_aton(ip_str))[0]
                except:
                    return None

            def int_to_ip(ip_int):
                try:
                    return socket.inet_ntoa(struct.pack("!I", int(ip_int)))
                except:
                    return "Invalid IP"

            df.iloc[:, 2] = df.iloc[:, 2].str.replace('.', '')
            #df.iloc[:, 3] = df.iloc[:, 3].str.replace('.', '')
            df.iloc[:, 3] = df.iloc[:, 3].apply(ip_str_to_int)
            df.iloc[:, 5] = df.iloc[:, 5].str.replace('.', '')
            
            df = df[df.iloc[:, 3].notnull()]
            X = df.iloc[:, :].values.astype('float64')

            if X.shape[0] == 0:
                self.logger.error("📛 No valid rows in prediction file after preprocessing.")
                self.logger.info("------------------------------------------------------------------------------")
                return

            preds = self.flow_model.predict(X)

            legitimate_traffic = 0
            ddos_traffic = 0

            for pred in preds:
                if pred == 0:
                    legitimate_traffic += 1
                else:
                    ddos_traffic += 1

            if (legitimate_traffic / len(preds) * 100) > 80:
                self.logger.info("legitimate traffic ...")
                self.logger.info("------------------------------------------------------------------------------")
            else:
                for i, pred in enumerate(preds):
                    ip = df.iloc[i, 3]
                    ip = int_to_ip(ip)
                    dpid = int(df.iloc[i, 1])
                    timestamp = int(df.iloc[i, 0])

                    if pred == 1:
                        self.logger.info("🚨 DDoS Attempt Detected from IP: %s", ip)

                        # Step 1: Apply Rate Limiting
                        self.apply_rate_limit(ip, dpid)
                        self.logger.info("🔒 Rate Limit Applied – Traffic Throttled")

                        # Step 2: Deep Learning Verification
                        deep_features = X[i].reshape(1, -1)
                        deep_pred = self.deep_model.predict(deep_features)
                        if deep_pred[0][0] > 0.5:
                            self.logger.info("🧠 Deep Learning Model: Attack Confirmed")

                            # Step 3: Threat Intelligence
                            if self.check_threat_intel(ip):
                                self.logger.info("🛡 Threat Intelligence: IP found in blacklist (known attacker)")
                            else:
                                self.logger.info("🛡 Threat Intelligence: IP not found in blacklist (new attacker – added to local blacklist)")

                            # Step 4: Blockchain Logging
                            try:
                                self.log_to_blockchain(ip, timestamp)
                            except:
                                self.logger.warning("🔗 Blockchain Log: Failed")

                            # Step 5: Apply SYN Proxy
                            self.apply_syn_proxy(ip, dpid)
                            self.logger.info("🧱 SYN Proxy Activated – SYN Flood Blocked")

                            # Final Result
                            self.logger.info("✅ RESULT: DDoS attack successfully detected and mitigated – no service disruption occurred.")
                            self.logger.info("----------------------------------------------------------------------------------")
                    break
        except Exception as e:
            self.logger.error("Prediction error: %s", str(e))

    
    def check_threat_intel(self, ip):
        # Step 1: Check local blacklist
        try:
            with open("local_blacklist.txt", "r") as f:
                local_blacklist = set(line.strip() for line in f.readlines())
        except FileNotFoundError:
            local_blacklist = set()

        if ip in local_blacklist:
            return True  # IP is locally blacklisted

        # Step 2: Check AbuseIPDB API
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {"Key": self.api_key, "Accept": "application/json"}

        try:
            response = requests.get(url, headers=headers)
            data = response.json()
            abuse_score = data['data']['abuseConfidenceScore']

            if abuse_score > 50:
                return True  # Attacker
            else:
                # New attacker – add to local blacklist
                with open("local_blacklist.txt", "a") as f:
                    f.write(f"{ip}\n")
                return False  # New attacker
        except:
            return False

    def connect_to_contract(self):
        abi = [{
		"anonymous": False,
		"inputs": [
			{
				"indexed": False,
				"internalType": "string",
				"name": "rule",
				"type": "string"
			},
			{
				"indexed": False,
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			}
		],
		"name": "PolicyAdded",
		"type": "event"
	   },
	   {
		"inputs": [
			{
				"internalType": "string",
				"name": "_rule",
				"type": "string"
			}
		],
		"name": "addPolicy",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	    },
	    {
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_index",
				"type": "uint256"
			}
		],
		"name": "getPolicy",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	    },
	    {
		"inputs": [],
		"name": "getPolicyCount",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	    },
	    {
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "policies",
		"outputs": [
			{
				"internalType": "string",
				"name": "rule",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	    }]  # Smart contract ABI
        address = self.web3.to_checksum_address("0xd9145CCE52D386f254917e481eB44e9943F39138")
        return self.web3.eth.contract(address=address, abi=abi)


    def log_to_blockchain(self, ip, timestamp):
        self.logger.info("🚀 Trying to log to blockchain...") 
        try:
            description = f"DDoS from {ip} at {timestamp}"

            # Step 1: Send transaction
            tx_hash = self.contract.functions.addPolicy(description).transact({'from': self.web3.eth.accounts[0]})

            # Step 2: Wait for confirmation
            tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

            if tx_receipt.status == 1:
                tx_hash_hex = tx_hash.hex()
                self.logger.info("⛓ Logged to blockchain ✅ TxHash: %s", tx_hash_hex)
                self.logger.info("🔗 Blockchain Log: Event recorded successfully")

                # Step 3: Save to local log file
                self.save_ddos_log(ip, timestamp, tx_hash_hex)
            else:
                self.logger.warning("⛓ Blockchain log failed ❌ (transaction reverted)")

        except Exception as e:
            self.logger.error("Blockchain error: %s", str(e))


    def save_ddos_log(self, ip, timestamp, tx_hash):
        file_name = "ddos_blockchain_logs.csv"
        file_exists = os.path.isfile(file_name)

        with open(file_name, mode='a', newline='') as file:
            writer = csv.writer(file)
            if not file_exists:
                writer.writerow(["IP Address", "Timestamp", "Transaction Hash"])
            writer.writerow([ip, timestamp, tx_hash])
        
        self.logger.info("📝 Local log updated with IP %s", ip)


    def apply_syn_proxy(self, ip, dpid):
        if dpid not in self.datapaths:
            self.logger.warning("❌ DPID %s not found in datapaths.", dpid)
            return

        datapath = self.datapaths[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip, tcp_flags=0x02)
        actions = []  # Drop SYN packet
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=101, match=match, instructions=inst)
        datapath.send_msg(mod)

        # Update counter
        self.syn_attack_counter[ip] = self.syn_attack_counter.get(ip, 0) + 1
        attack_count = self.syn_attack_counter[ip]

        with open("syn_attacks.log", "a") as log_file:
            log_file.write(f"[{datetime.now()}] SYN Flood Attempt from {ip} on switch {dpid} (Count: {attack_count})\n")

        self.logger.info("🛡 SYN Proxy applied to %s (attempt #%d)", ip, attack_count)

        if attack_count >= 3:
            self.logger.warning("🚨 Multiple SYN Flood attempts from %s (Total: %d)", ip, attack_count)

            # Blockchain Logging
            timestamp = int(datetime.now().timestamp())
            try:
                self.log_to_blockchain(ip, timestamp)
            except:
                self.logger.warning("❌ Failed to log SYN attack to blockchain.")

            # Final Defense – block all traffic from that IP
            match_block_all = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            inst_block_all = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
            mod_block_all = parser.OFPFlowMod(datapath=datapath, priority=110, match=match_block_all, instructions=inst_block_all)
            datapath.send_msg(mod_block_all)

            self.logger.info("🔒 All traffic blocked from %s due to repeated SYN attacks.", ip)

            # Save to local blacklist
            with open("local_blacklist.txt", "a") as f:
                f.write(f"{ip}\n")


    def apply_rate_limit(self, ip, dpid):
        if dpid in self.datapaths:
            datapath = self.datapaths[dpid]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            actions = []  # Drop
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst)
            datapath.send_msg(mod)
            self.logger.info("🔒 Rate Limit (Drop) applied to %s", ip)


   
