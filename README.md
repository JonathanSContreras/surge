# Surge

Surge is an advanced penetration testing framework that leverages Artificial Intelligence (AI) and Machine Learning (ML) to automate security testing and vulnerability assessment for target networks. The tool is designed to intelligently assess network stacks and topologies, detect vulnerabilities, prioritize them based on risk and impact, and suggest remediation strategies. A user-friendly web application provides a comprehensive overview, allowing security professionals to quickly understand potential threats, review exploit details, and implement solutions.

## Table of Contents
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Technologies and Tools](#technologies-and-tools)
- [Contributing](#contributing)
- [Contact](#contact)
- [License](#license)
 
## Key Features
- **Network Topology Mapping**
    The system traces the network stack to visualize the network architecture, identifying connected devices, open ports, and potential entry points.

- **Automated Vulnerability Detection**
    AI-driven modules scan networks to detect vulnerabilities by comparing known attack patterns and signatures while also learning from patterns across different network environments.

- **Risk Assessment and Prioritization**
    Each vulnerability is assigned a severity rating based on factors such as exploitability, potential impact, and existing countermeasures. This prioritization assists in focusing remediation efforts on the most critical issues.

- **Smart Test Recommendations**
    Leveraging machine learning, the framework suggests specific penetration tests and security measures tailored to the target network’s configuration and known vulnerabilities.

- **Web Application Dashboard**
    A responsive, intuitive web interface provides real-time reporting:
	- **Dashboard:** Summaries of discovered vulnerabilities, risk scores, and testing progress.
	- **Detail Views:** In-depth information on each vulnerability, including potential exploits and mitigation strategies.
	- **Historical Data:** Logs and past assessment reports to monitor trends and improvements over time.

## Architecture
The application is modular, separating concerns across several components:
1. Data Collection Module
	- Responsible for network scanning and topology mapping.
	- Uses both active and passive scanning techniques to gather detailed network information.
2.	AI/ML Engine
	- Processes raw data from the scan.
	- Applies classification algorithms, anomaly detection, and predictive analytics to identify vulnerabilities.
	- Continuously learns from new network behaviors and attack patterns to improve accuracy.
3.	Vulnerability Assessment & Prioritization
	- Integrates threat intelligence databases to compare findings with known vulnerabilities.
	- Calculates risk scores using weighted criteria such as exploit complexity, impact metrics, and asset importance.
4.	Web Application Frontend
	- Built with modern web technologies (such as React, Angular, or Vue.js) to provide a dynamic and user-friendly experience.
	- Displays vulnerability status, network maps, and detailed reports in real time.
5.	API and Integration Layer
	- Exposes RESTful endpoints for interfacing with third-party security tools and automation systems.
	- Supports integration with CI/CD pipelines and security information and event management (SIEM) systems.

## Technologies and Tools

### Web Application Tech Stack

**Core Framework**
- **Next.js 15** - A React-based framework that provides server-side rendering, static site generation, and optimal performance out of the box. Chosen for its excellent developer experience, built-in optimization features, and seamless deployment capabilities.

**Language & Type Safety**
- **TypeScript 5** - Provides static typing and enhanced IDE support, reducing bugs and improving code maintainability. Essential for building a reliable security tool where type safety can prevent critical errors.

**UI & Styling**
- **React 19** - The latest version of React offers improved performance and modern features for building interactive user interfaces. Its component-based architecture makes it ideal for creating the complex dashboards and visualization components needed for security reporting.
- **Tailwind CSS v4** - A utility-first CSS framework that enables rapid UI development with consistent design patterns. Chosen for its flexibility, performance, and ease of creating responsive, professional interfaces.

**Development Tools**
- **Turbopack** - Next.js's next-generation bundler that significantly speeds up development and build times, making the development workflow more efficient.
- **ESLint 9** - Ensures code quality and consistency across the codebase through automated linting.

**Backend & AI/ML Components**
- **Programming Languages:** Python (for backend scanning, AI/ML modules)
- **Machine Learning Libraries:** TensorFlow, Scikit-learn, PyTorch (depending on the algorithm requirements)
- **Database:** PostgreSQL, MongoDB, or another preferred solution for storing scan results and historical data
- **Security Tools and Libraries:** Nmap (for network scanning), OpenVAS or similar for vulnerability templates, integrated with custom modules

### Why This Stack?

This tech stack was chosen to balance performance, developer productivity, and user experience:
- **Performance First:** Next.js with Turbopack and React 19 ensure the dashboard loads quickly and remains responsive even with large datasets from network scans.
- **Type Safety:** TypeScript reduces runtime errors in a security-critical application where reliability is paramount.
- **Modern UI/UX:** React and Tailwind enable building intuitive, professional interfaces that security professionals need for quick threat assessment.
- **Scalability:** The modular architecture supports future expansion, API integrations, and real-time data updates.
- **Developer Experience:** The combination of these tools provides excellent debugging, hot reloading, and a smooth development workflow, enabling faster iteration on security features.


## Contributing
Contributions are welcome! Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on how to report issues or suggest improvements.

## Contact
For further information, questions, or contributions, please reach out to:
Jonathan Contreras – jonathansaulcontreras@gmail.com
Brianna Hinds - 

## License
This project is licensed under the MIT License.