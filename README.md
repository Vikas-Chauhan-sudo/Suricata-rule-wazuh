# Suricata-rule-wazuh

This repository contains custom Suricata rules designed to enhance threat detection and monitoring for Wazuh deployments. These rules focus on identifying malicious activity in DNS and HTTP traffic, including potential supply chain attacks and anomalous behavior.

## Features

- **DNS Rules**: Detect suspicious DNS queries, such as those related to the 3CX supply chain compromise, and identify anomalies like invalid opcodes and Z-flag usage.
- **HTTP Rules**: Monitor for malicious HTTP requests, such as downloads of malicious `.ICO` files from known compromised sources.
- **Easy Integration**: The rules can be seamlessly integrated into existing Suricata setups.


## Explore More

I have uploaded the full documentation and additional insights on Medium. Check out my profile for more cybersecurity content:
[Medium Profile - Vikas Chauhan](https://medium.com/@attvikas.chauhan)

If you like to connect with me professionally, feel free to reach out on LinkedIn:
[LinkedIn Profile - Vikas Chauhan](https://linkedin.com/in/vikas-chauhan-229786197)

## Contribution

Contributions are welcome! If you have additional rules or improvements, feel free to submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

