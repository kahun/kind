# Cloud Contributing Guidelines

This guide serves to set clear expectations for everyone involved with the project so that we can improve it together. Following these guidelines will help to ensure a positive experience for every maintainer.

## General workflow

Here's the general workflow to follow for every change to the code in this repository:

- A new functionality is proposed and accepted by the team, then the corresponding Jira ticket is created.
- During the team's sprint planning, the team will add the required detail to the Jira ticket.
- A developer then creates a Pull Request with the labels _wip_ + _dont merge_.
- When the functionality is implemented, the developer will then change the PR labels to _ok-to-review_ (deleting the previous ones).
- Another developer (peer) reviews the PR, testing it minimally and ensuring the code meets the standards (such as correctness, readability, maintainability and consistency).
- Once the review is done, the peer will change the PR labels to _ok-to-test_.
- At this point, the QA engineer will do the testing and evaluate if the PR adds the funcionality described and doesn't compromise any other.
- When the PR is ready to be merge, the QA engineer set the label _ok-to-merge_.
- The developer then can merge the PR at anytime. In case the funcionality has several PRs, the developer will merge them in the correct order.

If the PR requires changes in the documentation or tests, the developer should open them separately. 

## Special labels

### Releasing and PRs classification

The following labels should be use to ease the releasing process:

<release>: A label for each release is created in order to manage which PR is included. (e.g. "0.4.1").
documentation: Indicates that the PR requires the documentation team to review it.
cherry-pick: When the functionality must be present in existing branches, this label must be use in those PRs (they must have the same name as the original PR).
bugfix: For PRs that closes bugs.
feature: For when the PR implements a new functionality.

### CICD flow

Jenkins has its own labels to control whether or not to execute Unit tests ("skip doUT") or security scans ("skip doGrypeScan").

### Testing

AT-<provider/flavour>-smoke: These labels execute smoke tests on the specific cloud provider/flavour as part of the PR validations (e.g. "AT-eks-smoke" for EKS).

## Getting Started

To get started with this project, please read the documentation first.

- Official Documentation (published): http://antora.labs.stratio.com/es/cloud-provisioner/0.4/introduction.html
- Official Documentation (unpublished): [stratio-docs](stratio-docs/en/modules/ROOT/pages/quick-start-guide.adoc)

## Contact Information

The maintainer's team can be reached on this [email](clouds-integration@stratio.com), but preffer the Stratio internal channels.

