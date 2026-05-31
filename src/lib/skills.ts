export interface Skill {
  name: string;
  description: string;
}

export const skills: Skill[] = [
  {
    name: "Java",
    description:
      "Used Java extensively in university coursework and early professional projects, including building backend services and data pipelines. Comfortable with the JVM ecosystem and concurrency primitives.",
  },
  {
    name: "Python",
    description:
      "My go-to language for data science, NLP, and scripting. Used it professionally for years across ML model training, ETL pipelines, and AI system prototypes.",
  },
  {
    name: "JS",
    description:
      "Comfortable with modern JavaScript for both browser and Node.js environments. Used for frontend interactivity, WebSocket servers, and rapid prototyping.",
  },
  {
    name: "TypeScript",
    description:
      "Prefer TypeScript over plain JS for any project of meaningful size. This portfolio is written in TypeScript — type safety catches whole classes of bugs before they ship.",
  },
  {
    name: "Go",
    description:
      "Built the Fishing Game entirely in Go using the Ebiten engine, compiled to WebAssembly. Drawn to Go for its simplicity, fast compile times, and strong concurrency model.",
  },
  {
    name: "Rust",
    description:
      "Working knowledge of Rust through systems programming exercises and the CodexBar KDE port. Appreciate the memory-safety guarantees and the expressive type system.",
  },
  {
    name: "Bash",
    description:
      "Heavy user of Bash for automation and infrastructure scripting. The entire deploy pipeline for this portfolio — local setup, cloud provisioning, Ansible orchestration — is driven by a single Bash script.",
  },
  {
    name: "Next.js",
    description:
      "Built this portfolio in Next.js. Appreciate the file-based routing, server components, and the seamless way it handles environment variables between build and runtime.",
  },
  {
    name: "SQL",
    description:
      "Experienced with relational databases (PostgreSQL, SQLite, MySQL) for application data modelling, query optimisation, and schema migrations in production systems.",
  },
  {
    name: "NoSQL",
    description:
      "Worked with document stores and key-value systems at scale. Understand the trade-offs between consistency, availability, and partition tolerance in distributed data layers.",
  },
  {
    name: "AWS",
    description:
      "Professional experience deploying and managing services on AWS — EC2, S3, IAM, VPC, and more. This portfolio can deploy its projects to AWS automatically via the deploy script.",
  },
  {
    name: "GCP",
    description:
      "Used GCP for cloud infrastructure including Compute Engine and Cloud Storage. The Flowers demo is hosted on a GCP instance, provisioned automatically by Ansible.",
  },
  {
    name: "Azure",
    description:
      "Used Azure VMs and Blob Storage in professional and personal projects. This portfolio itself is hosted on an Azure instance, with HTTPS via an Azure DNS label.",
  },
  {
    name: "AI/ML",
    description:
      "Five years of professional experience in applied AI and ML — from classical NLP models to modern LLMs. Comfortable across the full lifecycle: data, training, evaluation, and serving.",
  },
  {
    name: "NLP",
    description:
      "NLP was the core of my professional work for several years. Built and deployed production NLP systems for information extraction, classification, and search at scale.",
  },
  {
    name: "Agentic Systems",
    description:
      "Currently focused on the frontier of agentic development. This portfolio is itself a demonstration — the codebase, deployment scripts, and cloud infrastructure were all built collaboratively with AI agents.",
  },
  {
    name: "Distributed Systems",
    description:
      "Worked on distributed computing at scale professionally — fault tolerance, consensus, replication, and the operational realities of running services across many nodes.",
  },
  {
    name: "Data Persistence",
    description:
      "Deep experience with storage technologies: relational databases, object storage, distributed file systems, and caching layers. Understand the durability and consistency trade-offs in each.",
  },
  {
    name: "ETL",
    description:
      "Designed and maintained ETL pipelines in professional settings, moving and transforming large volumes of data between storage systems, often with strict SLA requirements.",
  },
  {
    name: "Data Flows",
    description:
      "Experience designing end-to-end data flow architectures — from ingestion and transformation through to serving and monitoring — with an eye toward reliability and observability.",
  },
  {
    name: "Scrum",
    description:
      "Worked in and facilitated Scrum teams for the majority of my professional career: sprint planning, retrospectives, backlog grooming, and the disciplines that make iterative delivery work in practice. Know when to use and when not to use Scrum practices.",
  },
  {
    name: "Hosting",
    description:
      "Hands-on experience with cloud hosting across AWS, GCP, Azure, and OCI. This portfolio handles fully automated VM provisioning, HTTPS, and zero-downtime refreshes across all four providers.",
  },
  {
    name: "Kubernetes",
    description:
      "Worked with Kubernetes for container orchestration in professional environments — deployments, services, config maps, and the operational patterns needed to keep clusters healthy.",
  },
  {
    name: "Authn/z",
    description:
      "Implemented authentication and authorization systems professionally, including OAuth2, JWT, RBAC, TLS, mTLS, and the security patterns needed to protect APIs and user data at scale.",
  },
];
