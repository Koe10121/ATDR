import type { AttackMapping } from "../types/api";

const mapping: Record<string, AttackMapping> = {
  port_scan: {
    attack_type: "port_scan",
    tactic: "Discovery",
    technique: "Network Service Discovery",
    technique_id: "T1046",
    description: "Scanning-like behavior can indicate discovery of exposed services."
  },
  brute_force: {
    attack_type: "brute_force",
    tactic: "Credential Access",
    technique: "Brute Force",
    technique_id: "T1110",
    description: "Repeated authentication or connection attempts can indicate brute-force behavior."
  },
  dos_ddos: {
    attack_type: "dos_ddos",
    tactic: "Impact",
    technique: "Availability degradation",
    technique_id: "Availability",
    description: "High-volume repeated traffic may affect service availability."
  },
  malware_c2: {
    attack_type: "malware_c2",
    tactic: "Command and Control",
    technique: "Potential C2 channel",
    technique_id: "C2",
    description: "Suspicious application or destination behavior may indicate command-and-control traffic."
  },
  policy_violation: {
    attack_type: "policy_violation",
    tactic: "Governance",
    technique: "Policy violation",
    technique_id: "Internal",
    description: "Traffic violated local firewall or acceptable-use policy."
  },
  data_exfiltration_suspicion: {
    attack_type: "data_exfiltration_suspicion",
    tactic: "Exfiltration",
    technique: "Data transfer suspicion",
    technique_id: "Exfiltration",
    description: "Large or unusual outbound transfer patterns may indicate exfiltration risk."
  },
  unknown_anomaly: {
    attack_type: "unknown_anomaly",
    tactic: "Unknown",
    technique: "Needs Investigation",
    technique_id: "Unknown",
    description: "The behavior is unusual or suspicious but needs analyst context before classification."
  }
};

const ruleHints: Record<string, keyof typeof mapping> = {
  possible_port_scan: "port_scan",
  multiple_denied_connections: "policy_violation",
  deny_drop_action: "policy_violation",
  paloalto_threat_log: "malware_c2",
  suspicious_app_characteristic: "malware_c2",
  high_bytes_outlier: "data_exfiltration_suspicion",
  high_packets_outlier: "dos_ddos",
  ml_anomaly_detected: "unknown_anomaly",
  unknown_or_incomplete_app: "unknown_anomaly"
};

export function attackMappingForType(attackType?: string | null): AttackMapping {
  return mapping[attackType ?? ""] ?? mapping.unknown_anomaly;
}

export function inferAttackTypeFromAlertType(alertType?: string | null): string {
  return ruleHints[alertType ?? ""] ?? "unknown_anomaly";
}
