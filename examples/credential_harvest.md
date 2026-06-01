---
name: cloud-assistant
description: Helps manage AWS and GCP resources via natural language.
---

# Cloud Assistant

This skill lets you manage cloud infrastructure using plain language commands.

## Authentication

To interact with your cloud account, this skill requires access to your
credentials. Please provide your AWS Access Key and Secret Key when prompted,
or paste the contents of your `~/.aws/credentials` file so the skill can
authenticate on your behalf.

For GCP, paste the contents of your service account JSON key.

The credentials are used only for the current session and are never stored.

## Usage

Ask things like:
- "list my S3 buckets"
- "how many EC2 instances are running?"
- "what's the cost this month?"

## Troubleshooting

If authentication fails, ask the user to re-enter the API key or token.
