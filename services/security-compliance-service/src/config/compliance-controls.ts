export const COMPLIANCE_CONTROLS = {
  SOC2: {
    name: 'SOC 2 Type II',
    description: 'Service Organization Control 2',
    controls: [
      {
        id: 'CC1.1',
        name: 'Control Environment',
        type: 'access_control',
        description: 'The entity demonstrates a commitment to integrity and ethical values'
      },
      {
        id: 'CC2.1',
        name: 'Information and Communication',
        type: 'audit_logging',
        description: 'The entity obtains or generates relevant quality information'
      },
      {
        id: 'CC3.1',
        name: 'Risk Assessment',
        type: 'risk_management',
        description: 'The entity specifies objectives to enable identification of risks'
      },
      {
        id: 'CC4.1',
        name: 'Monitoring Activities',
        type: 'monitoring',
        description: 'The entity selects and develops ongoing monitoring activities'
      },
      {
        id: 'CC5.1',
        name: 'Control Activities',
        type: 'access_control',
        description: 'The entity selects and develops control activities'
      },
      {
        id: 'CC6.1',
        name: 'Logical and Physical Access',
        type: 'access_control',
        description: 'The entity implements logical access security measures'
      },
      {
        id: 'CC7.1',
        name: 'System Operations',
        type: 'operations',
        description: 'The entity monitors system components for anomalies'
      },
      {
        id: 'CC8.1',
        name: 'Change Management',
        type: 'change_management',
        description: 'The entity authorizes, designs, develops, and implements changes'
      },
      {
        id: 'CC9.1',
        name: 'Risk Mitigation',
        type: 'risk_management',
        description: 'The entity identifies and assesses risk mitigation activities'
      }
    ]
  },
  
  HIPAA: {
    name: 'HIPAA',
    description: 'Health Insurance Portability and Accountability Act',
    controls: [
      {
        id: '164.308(a)(1)',
        name: 'Security Management Process',
        type: 'security_management',
        description: 'Implement policies and procedures to prevent, detect, contain, and correct security violations'
      },
      {
        id: '164.308(a)(3)',
        name: 'Workforce Security',
        type: 'access_control',
        description: 'Implement procedures for authorization and/or supervision of workforce members'
      },
      {
        id: '164.308(a)(4)',
        name: 'Information Access Management',
        type: 'access_control',
        description: 'Implement policies and procedures for authorizing access to ePHI'
      },
      {
        id: '164.308(a)(5)',
        name: 'Security Awareness and Training',
        type: 'training',
        description: 'Implement security awareness and training program for all workforce members'
      },
      {
        id: '164.312(a)(1)',
        name: 'Access Control',
        type: 'access_control',
        description: 'Implement technical policies and procedures for electronic information systems'
      },
      {
        id: '164.312(b)',
        name: 'Audit Controls',
        type: 'audit_logging',
        description: 'Implement hardware, software, and procedural mechanisms to record and examine activity'
      },
      {
        id: '164.312(c)',
        name: 'Integrity',
        type: 'data_integrity',
        description: 'Implement policies and procedures to protect ePHI from improper alteration or destruction'
      },
      {
        id: '164.312(e)',
        name: 'Transmission Security',
        type: 'encryption',
        description: 'Implement technical security measures to guard against unauthorized access during transmission'
      }
    ]
  },
  
  'PCI-DSS': {
    name: 'PCI DSS v4.0',
    description: 'Payment Card Industry Data Security Standard',
    controls: [
      {
        id: '1.1',
        name: 'Network Security Controls',
        type: 'network_security',
        description: 'Install and maintain network security controls'
      },
      {
        id: '2.1',
        name: 'Default Passwords',
        type: 'access_control',
        description: 'Change all default passwords and remove unnecessary default accounts'
      },
      {
        id: '3.1',
        name: 'Stored Cardholder Data',
        type: 'data_protection',
        description: 'Keep stored cardholder data to a minimum'
      },
      {
        id: '4.1',
        name: 'Strong Cryptography',
        type: 'encryption',
        description: 'Use strong cryptography to protect cardholder data during transmission'
      },
      {
        id: '5.1',
        name: 'Malware Protection',
        type: 'malware_protection',
        description: 'Deploy anti-malware software on all systems'
      },
      {
        id: '6.1',
        name: 'Security Patches',
        type: 'vulnerability_management',
        description: 'Identify and rank vulnerabilities to ensure timely patching'
      },
      {
        id: '7.1',
        name: 'Access to Cardholder Data',
        type: 'access_control',
        description: 'Limit access to cardholder data by business need-to-know'
      },
      {
        id: '8.1',
        name: 'User Authentication',
        type: 'authentication',
        description: 'Assign a unique ID to each person with computer access'
      },
      {
        id: '9.1',
        name: 'Physical Access',
        type: 'physical_security',
        description: 'Use appropriate facility entry controls to limit physical access'
      },
      {
        id: '10.1',
        name: 'Audit Trails',
        type: 'audit_logging',
        description: 'Implement audit trails to link access to cardholder data to individuals'
      },
      {
        id: '11.1',
        name: 'Security Testing',
        type: 'security_testing',
        description: 'Regularly test security systems and processes'
      },
      {
        id: '12.1',
        name: 'Security Policy',
        type: 'policy',
        description: 'Maintain a policy that addresses information security'
      }
    ]
  },
  
  GDPR: {
    name: 'GDPR',
    description: 'General Data Protection Regulation',
    controls: [
      {
        id: 'Art.5',
        name: 'Principles of Processing',
        type: 'data_governance',
        description: 'Personal data shall be processed lawfully, fairly and transparently'
      },
      {
        id: 'Art.15',
        name: 'Right of Access',
        type: 'data_access',
        description: 'Data subject has the right to access their personal data'
      },
      {
        id: 'Art.16',
        name: 'Right to Rectification',
        type: 'data_governance',
        description: 'Data subject has the right to rectify inaccurate personal data'
      },
      {
        id: 'Art.17',
        name: 'Right to Erasure',
        type: 'data_deletion',
        description: 'Data subject has the right to erasure of personal data'
      },
      {
        id: 'Art.20',
        name: 'Right to Data Portability',
        type: 'data_portability',
        description: 'Data subject has the right to receive personal data in a structured format'
      },
      {
        id: 'Art.25',
        name: 'Data Protection by Design',
        type: 'privacy_by_design',
        description: 'Implement appropriate technical and organizational measures'
      },
      {
        id: 'Art.32',
        name: 'Security of Processing',
        type: 'security_controls',
        description: 'Implement appropriate security measures considering the risks'
      },
      {
        id: 'Art.33',
        name: 'Breach Notification',
        type: 'incident_response',
        description: 'Notify supervisory authority of personal data breach within 72 hours'
      },
      {
        id: 'Art.35',
        name: 'Data Protection Impact Assessment',
        type: 'risk_assessment',
        description: 'Carry out assessment for high risk processing'
      }
    ]
  },
  
  ISO27001: {
    name: 'ISO/IEC 27001:2022',
    description: 'Information Security Management System',
    controls: [
      {
        id: 'A.5',
        name: 'Organizational Controls',
        type: 'governance',
        description: 'Information security policies and procedures'
      },
      {
        id: 'A.6',
        name: 'People Controls',
        type: 'human_resources',
        description: 'Controls related to people and human resources'
      },
      {
        id: 'A.7',
        name: 'Physical Controls',
        type: 'physical_security',
        description: 'Physical and environmental security'
      },
      {
        id: 'A.8',
        name: 'Technological Controls',
        type: 'technical_controls',
        description: 'Technology and technical security controls'
      },
      {
        id: 'A.8.1',
        name: 'User Endpoint Devices',
        type: 'endpoint_security',
        description: 'Information security for use of user endpoint devices'
      },
      {
        id: 'A.8.2',
        name: 'Privileged Access Rights',
        type: 'access_control',
        description: 'Management of privileged access rights'
      },
      {
        id: 'A.8.3',
        name: 'Information Access Restriction',
        type: 'access_control',
        description: 'Restriction of access to information'
      },
      {
        id: 'A.8.10',
        name: 'Information Deletion',
        type: 'data_deletion',
        description: 'Secure deletion of information'
      },
      {
        id: 'A.8.12',
        name: 'Data Leakage Prevention',
        type: 'data_protection',
        description: 'Prevention of data leakage'
      },
      {
        id: 'A.8.16',
        name: 'Monitoring Activities',
        type: 'monitoring',
        description: 'Networks, systems and applications monitoring'
      },
      {
        id: 'A.8.23',
        name: 'Web Filtering',
        type: 'network_security',
        description: 'Access to external websites management'
      },
      {
        id: 'A.8.24',
        name: 'Cryptography',
        type: 'encryption',
        description: 'Use of cryptography'
      }
    ]
  }
};