from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from .matching import granting_statements, is_admin_equivalent, is_specifically_scoped, patterns_granting
from .parser import ParsedPolicy, Statement


@dataclass
class EscalationFinding:
    name: str
    severity: str  # "CRITICAL", "HIGH" or "MEDIUM"
    description: str
    attack_path: str
    remediation: str
    involved_actions: list[str]
    statement_indexes: list[int]
    id: str = ""
    granted_by: list[str] = field(default_factory=list)
    note: str = ""


# Definition of known AWS privilege escalation vectors (based on Rhino Security Labs research)
# Each vector has:
# - name: descriptive title
# - severity: CRITICAL or HIGH
# - required_groups: list of concrete action requirements. All groups must be satisfied for the vector to trigger.
#   A group is satisfied if ANY action in that group is granted by an Allow statement (and not explicitly denied).
# - pass_to: (PassRole vectors) service principals the role is passed to, checked against iam:PassedToService
# - self_scoped_safe: vector does not apply when the resource is limited to the caller (${aws:username})
# - self_scope_dangerous: scoping to the caller's own identity does NOT reduce the risk (e.g. attach admin to self)
# - description: summary of the risk
# - attack_path: step-by-step exploitation explanation
# - remediation: actionable fix
ESCALATION_VECTORS = [
    {
        "id": "passrole-lambda",
        "pass_to": ["lambda.amazonaws.com"],
        "name": "PassRole + Lambda Code Execution",
        "severity": "CRITICAL",
        "required_groups": [
            ["iam:PassRole"],
            ["lambda:CreateFunction", "lambda:UpdateFunctionCode"],
            ["lambda:InvokeFunction", "lambda:InvokeFunctionUrl", "lambda:CreateFunctionUrlConfig", "lambda:CreateEventSourceMapping"],
        ],
        "description": "Can pass a high-privilege IAM role to a new or modified Lambda function and invoke it to execute arbitrary commands.",
        "attack_path": (
            "1. Attacker crafts a Lambda function containing malicious credential-stealing or administrative code.\n"
            "2. Attacker attaches a privileged IAM role (e.g. administrator or power user) using iam:PassRole.\n"
            "3. Attacker invokes the function (directly, via a function URL, or via an event source) to run code as that role."
        ),
        "remediation": "Restrict iam:PassRole using 'iam:PassedToService' condition to specific services and scope Resource to non-privileged roles.",
    },
    {
        "id": "passrole-ec2",
        "pass_to": ["ec2.amazonaws.com"],
        "name": "PassRole + EC2 Instance Profile",
        "severity": "CRITICAL",
        "required_groups": [
            ["iam:PassRole"],
            ["ec2:RunInstances"],
        ],
        "description": "Can launch an EC2 instance with an existing privileged IAM instance profile and access credentials via IMDS.",
        "attack_path": (
            "1. Attacker launches a new EC2 instance with an existing privileged instance profile.\n"
            "2. Attacker accesses instance user data or SSH/SSM to query the EC2 Instance Metadata Service (IMDS).\n"
            "3. Attacker extracts temporary security credentials of the attached role."
        ),
        "remediation": "Restrict ec2:RunInstances and iam:PassRole so that instance profiles can only be attached to designated subnets/AMIs, or require approval.",
    },
    {
        "id": "passrole-cloudformation",
        "pass_to": ["cloudformation.amazonaws.com"],
        "name": "PassRole + CloudFormation Stack Execution",
        "severity": "CRITICAL",
        "required_groups": [
            ["iam:PassRole"],
            ["cloudformation:CreateStack", "cloudformation:UpdateStack"],
        ],
        "description": "Can pass a privileged service role to CloudFormation to deploy templates that grant admin permissions or create credentials.",
        "attack_path": (
            "1. Attacker creates a CloudFormation stack template declaring administrative IAM users or roles.\n"
            "2. Attacker passes a privileged IAM role to CloudFormation using iam:PassRole.\n"
            "3. CloudFormation provisions the resources with full permissions of the role."
        ),
        "remediation": "Restrict the RoleArn parameter in CloudFormation operations and enforce template review via change sets.",
    },
    {
        "id": "passrole-glue",
        "pass_to": ["glue.amazonaws.com"],
        "name": "PassRole + AWS Glue Execution",
        "severity": "CRITICAL",
        "required_groups": [
            ["iam:PassRole"],
            ["glue:CreateDevEndpoint", "glue:UpdateDevEndpoint", "glue:CreateJob", "glue:UpdateJob"],
        ],
        "description": "Can create or update a Glue development endpoint or job with a privileged role to execute arbitrary Python/Scala code.",
        "attack_path": (
            "1. Attacker creates or updates a Glue development endpoint or ETL job with a privileged IAM role.\n"
            "2. Attacker connects via SSH or triggers the job to run code that exfiltrates credentials or performs unauthorized actions."
        ),
        "remediation": "Scope iam:PassRole specifically to Glue service roles with strictly limited data-access permissions.",
    },
    {
        "id": "passrole-codebuild",
        "pass_to": ["codebuild.amazonaws.com"],
        "name": "PassRole + CodeBuild Arbitrary Build",
        "severity": "CRITICAL",
        "required_groups": [
            ["iam:PassRole"],
            ["codebuild:CreateProject", "codebuild:UpdateProject"],
            ["codebuild:StartBuild", "codebuild:StartBuildBatch"],
        ],
        "description": "Can configure a CodeBuild project with a custom buildspec that runs arbitrary shell commands with the project's service role.",
        "attack_path": (
            "1. Attacker creates or updates a CodeBuild project referencing a privileged service role.\n"
            "2. Attacker overrides the buildspec with commands to extract role credentials or create IAM users.\n"
            "3. Attacker triggers codebuild:StartBuild."
        ),
        "remediation": "Enforce strict CodeBuild project naming and scope iam:PassRole to vetted CodeBuild service roles.",
    },
    {
        "id": "passrole-ecs",
        "pass_to": ["ecs-tasks.amazonaws.com", "ecs.amazonaws.com"],
        "name": "PassRole + ECS Task Execution",
        "severity": "CRITICAL",
        "required_groups": [
            ["iam:PassRole"],
            ["ecs:RegisterTaskDefinition"],
            ["ecs:RunTask", "ecs:StartTask", "ecs:CreateService", "ecs:UpdateService"],
        ],
        "description": "Can register a container task definition with a privileged execution or task role and run it to harvest credentials.",
        "attack_path": (
            "1. Attacker registers an ECS task definition pointing to a malicious container image and high-privilege IAM task role.\n"
            "2. Attacker calls ecs:RunTask to launch the container.\n"
            "3. The container extracts temporary credentials from the task metadata endpoint."
        ),
        "remediation": "Limit ecs:RegisterTaskDefinition and iam:PassRole so task roles cannot be arbitrarily assigned without authorization.",
    },
    {
        "id": "passrole-datapipeline",
        "pass_to": ["datapipeline.amazonaws.com", "elasticmapreduce.amazonaws.com", "ec2.amazonaws.com"],
        "name": "PassRole + Data Pipeline Execution",
        "severity": "HIGH",
        "required_groups": [
            ["iam:PassRole"],
            ["datapipeline:CreatePipeline"],
            ["datapipeline:PutPipelineDefinition"],
        ],
        "description": "Can create a Data Pipeline that provisions EC2 resources running commands under an attached role.",
        "attack_path": (
            "1. Attacker creates a pipeline with datapipeline:CreatePipeline.\n"
            "2. Attacker provides a pipeline definition with datapipeline:PutPipelineDefinition containing shell commands.\n"
            "3. Pipeline runs the commands with the permissions of the assigned role."
        ),
        "remediation": "Restrict datapipeline:* actions and require explicit resource tagging and role approval.",
    },
    {
        "id": "create-access-key",
        "self_scoped_safe": True,
        "name": "Direct Credential Creation (iam:CreateAccessKey)",
        "severity": "HIGH",
        "required_groups": [
            ["iam:CreateAccessKey"],
        ],
        "description": "Can generate new long-term API access keys for any IAM user in the account.",
        "attack_path": (
            "1. Attacker identifies an existing high-privilege user (e.g. administrator or service account).\n"
            "2. Attacker calls iam:CreateAccessKey for that user.\n"
            "3. Attacker uses the generated AccessKeyId and SecretAccessKey to assume all permissions of that user."
        ),
        "remediation": "Scope Resource on iam:CreateAccessKey to '${aws:username}' so users can only manage their own keys, or deny access key creation altogether.",
    },
    {
        "id": "create-login-profile",
        "self_scoped_safe": True,
        "name": "Console Password Creation or Reset (iam:CreateLoginProfile / iam:UpdateLoginProfile)",
        "severity": "HIGH",
        "required_groups": [
            ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"],
        ],
        "description": "Can set or change the AWS Management Console password for arbitrary IAM users.",
        "attack_path": (
            "1. Attacker targets an existing administrative IAM user that lacks a console password or whose password can be changed.\n"
            "2. Attacker sets a known password using iam:CreateLoginProfile or iam:UpdateLoginProfile.\n"
            "3. Attacker logs into the AWS console as that user."
        ),
        "remediation": "Restrict iam:*LoginProfile using conditions or resource constraints so principals cannot reset other users' passwords.",
    },
    {
        "id": "attach-policy",
        "self_scope_dangerous": True,
        "name": "Direct Policy Attachment (iam:Attach*Policy)",
        "severity": "CRITICAL",
        "required_groups": [
            ["iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy"],
        ],
        "description": "Can attach existing managed policies (including AdministratorAccess) to any user, role, or group.",
        "attack_path": (
            "1. Attacker attaches the AWS-managed 'AdministratorAccess' policy to their current identity or a controlled role.\n"
            "2. Attacker instantly acquires full administrative access to the AWS account."
        ),
        "remediation": "Apply IAM permission boundaries, enforce strict Resource conditions, or manage policy attachments exclusively via Infrastructure as Code.",
    },
    {
        "id": "put-policy",
        "self_scope_dangerous": True,
        "name": "Inline Policy Injection (iam:Put*Policy)",
        "severity": "CRITICAL",
        "required_groups": [
            ["iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy"],
        ],
        "description": "Can write arbitrary inline IAM policies granting full administrative privileges.",
        "attack_path": (
            "1. Attacker injects an inline policy with 'Effect': 'Allow', 'Action': '*', 'Resource': '*' onto their identity or an assumable role.\n"
            "2. Attacker immediately acquires unrestricted administrative control."
        ),
        "remediation": "Deny iam:Put*Policy or use permissions boundaries to cap the maximum effective permissions.",
    },
    {
        "id": "add-user-to-group",
        "name": "Privileged Group Membership (iam:AddUserToGroup)",
        "severity": "HIGH",
        "required_groups": [
            ["iam:AddUserToGroup"],
        ],
        "description": "Can add users to existing privileged groups (e.g., Admins, SecurityAudit).",
        "attack_path": (
            "1. Attacker adds their user or a puppet user to an administrative IAM group.\n"
            "2. User inherits all managed and inline policies attached to that group."
        ),
        "remediation": "Scope Resource on iam:AddUserToGroup to non-sensitive groups or manage group membership through IAM Identity Center (SSO).",
    },
    {
        "id": "update-assume-role-policy",
        "name": "Trust Policy Backdoor (iam:UpdateAssumeRolePolicy)",
        "severity": "CRITICAL",
        "required_groups": [
            ["iam:UpdateAssumeRolePolicy"],
        ],
        "description": "Can alter the trust relationship of any role to allow the attacker to assume it.",
        "attack_path": (
            "1. Attacker modifies the trust policy of an administrative role to include the attacker's principal ARN.\n"
            "2. Attacker assumes the role via sts:AssumeRole and obtains full administrator privileges."
        ),
        "remediation": "Restrict iam:UpdateAssumeRolePolicy with strict Resource ARNs and require MFA or multi-party approval.",
    },
    {
        "id": "policy-versioning",
        "name": "Policy Version Tampering (iam:CreatePolicyVersion / iam:SetDefaultPolicyVersion)",
        "severity": "HIGH",
        "required_groups": [
            ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
        ],
        "description": "Can create a new default policy version containing full admin permissions or revert to an older permissive version.",
        "attack_path": (
            "1. Attacker creates a new version of an attached managed policy containing Action: * and Resource: *.\n"
            "2. Attacker sets it as the default version with setAsDefault=true, immediately escalating permissions for all attached entities."
        ),
        "remediation": "Restrict iam:CreatePolicyVersion and iam:SetDefaultPolicyVersion, and enforce version rotation in CI/CD pipelines.",
    },
    {
        "id": "ssm-remote-execution",
        "name": "Remote Command Execution via SSM (ssm:SendCommand / ssm:StartSession)",
        "severity": "HIGH",
        "required_groups": [
            ["ssm:SendCommand", "ssm:StartSession"],
        ],
        "description": "Can execute commands or open interactive shells on EC2 instances running with IAM instance profile credentials.",
        "attack_path": (
            "1. Attacker sends commands via SSM to an EC2 instance that runs under a privileged IAM role.\n"
            "2. Attacker queries the instance metadata service or reads local credentials to escalate privileges."
        ),
        "remediation": "Scope SSM commands with resource tags (e.g. ssm:resourceTag/Environment) and enable session logging to encrypted S3/CloudWatch.",
    },
    {
        "id": "lambda-update-code",
        "name": "Existing Lambda Code Hijack (lambda:UpdateFunctionCode)",
        "severity": "HIGH",
        "required_groups": [
            ["lambda:UpdateFunctionCode"],
        ],
        "description": "Can replace the code of existing Lambda functions, which then run with each function's own (possibly privileged) execution role.",
        "attack_path": (
            "1. Attacker lists functions and picks one whose execution role is more privileged than their own.\n"
            "2. Attacker uploads malicious code with lambda:UpdateFunctionCode.\n"
            "3. The next invocation (by its normal trigger) runs the attacker's code with the function's role."
        ),
        "remediation": "Scope lambda:UpdateFunctionCode to specific function ARNs owned by this workload, or require code signing (Lambda code signing configs).",
    },
    {
        "id": "passrole-sagemaker",
        "name": "PassRole + SageMaker Notebook",
        "severity": "HIGH",
        "pass_to": ["sagemaker.amazonaws.com"],
        "required_groups": [
            ["iam:PassRole"],
            ["sagemaker:CreateNotebookInstance"],
            ["sagemaker:CreatePresignedNotebookInstanceUrl"],
        ],
        "description": "Can create a SageMaker notebook instance with a privileged role and open a Jupyter shell on it.",
        "attack_path": (
            "1. Attacker creates a notebook instance and passes a privileged role to it.\n"
            "2. Attacker generates a presigned URL and opens the Jupyter terminal.\n"
            "3. Code in the notebook runs with the passed role's credentials."
        ),
        "remediation": "Scope iam:PassRole for SageMaker to dedicated, least-privilege notebook roles (use the iam:PassedToService condition).",
    },
    {
        "id": "glue-update-dev-endpoint",
        "name": "Glue Dev Endpoint Takeover (glue:UpdateDevEndpoint)",
        "severity": "HIGH",
        "required_groups": [
            ["glue:UpdateDevEndpoint"],
        ],
        "description": "Can add an SSH key to an existing Glue development endpoint and run code with its role.",
        "attack_path": (
            "1. Attacker adds their public SSH key to an existing dev endpoint with glue:UpdateDevEndpoint.\n"
            "2. Attacker SSHes in and uses the endpoint's role credentials."
        ),
        "remediation": "Scope glue:UpdateDevEndpoint to specific endpoints, or retire dev endpoints in favour of Glue interactive sessions.",
    },
    {
        "id": "codebuild-start-build",
        "name": "CodeBuild Buildspec Override (codebuild:StartBuild)",
        "severity": "HIGH",
        "required_groups": [
            ["codebuild:StartBuild", "codebuild:StartBuildBatch"],
        ],
        "description": "Can start builds of existing CodeBuild projects with an overridden buildspec, running arbitrary commands as the project's service role.",
        "attack_path": (
            "1. Attacker picks an existing project whose service role is privileged.\n"
            "2. Attacker calls codebuild:StartBuild with buildspecOverride containing their own commands.\n"
            "3. The build runs those commands with the project's role credentials."
        ),
        "remediation": "Scope codebuild:StartBuild to specific project ARNs and keep project service roles least-privilege.",
    },
    {
        "id": "permissions-boundary-removal",
        "self_scope_dangerous": True,
        "name": "Permissions Boundary Tampering (iam:Delete*/Put*PermissionsBoundary)",
        "severity": "HIGH",
        "required_groups": [
            [
                "iam:DeleteUserPermissionsBoundary",
                "iam:DeleteRolePermissionsBoundary",
                "iam:PutUserPermissionsBoundary",
                "iam:PutRolePermissionsBoundary",
            ],
        ],
        "description": "Can remove or replace the permissions boundary that caps a user's or role's effective permissions.",
        "attack_path": (
            "1. Attacker removes (or loosens) the permissions boundary on their own identity or a role they control.\n"
            "2. Policies already attached to that identity take full effect, beyond what the boundary allowed."
        ),
        "remediation": "Deny boundary changes for everyone except a dedicated admin role (e.g. with an SCP or explicit Deny).",
    },
    {
        "id": "ec2-instance-connect",
        "name": "SSH Key Injection (ec2-instance-connect:SendSSHPublicKey)",
        "severity": "HIGH",
        "required_groups": [
            ["ec2-instance-connect:SendSSHPublicKey", "ec2-instance-connect:SendSerialConsoleSSHPublicKey"],
        ],
        "description": "Can push a temporary SSH key to EC2 instances and log in, then use the instance role's credentials.",
        "attack_path": (
            "1. Attacker pushes their SSH public key to a target instance.\n"
            "2. Attacker logs in within 60 seconds and reads credentials from the instance metadata service."
        ),
        "remediation": "Scope EC2 Instance Connect to specific instances (by ARN or ec2:ResourceTag) and the expected OS user (ec2:osuser).",
    },
]


_SELF_SCOPE = "${aws:username}"
_LOWER = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW"}


def detect_privilege_escalations(policy: ParsedPolicy) -> list[EscalationFinding]:
    """Detect known AWS privilege escalation vectors across all statements of an identity policy.

    Honours NotAction, unconditional Deny statements, resource scoping, ``iam:PassedToService``
    conditions and ``${aws:username}`` self-scoping. Statements with a Principal (trust, bucket,
    key policies) are ignored: escalation is about what an identity can do.
    """
    # A policy that already grants (or can trivially grant itself) everything has nothing left to
    # escalate to; the "Full admin access" warning already reports it.
    if any(is_admin_equivalent(s) and not s.is_resource_based for s in policy.statements):
        return []

    findings: list[EscalationFinding] = []
    for vector in ESCALATION_VECTORS:
        finding = _evaluate_vector(policy, vector)
        if finding:
            findings.append(finding)
    findings.sort(key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(f.severity, 3))
    return findings


def _evaluate_vector(policy: ParsedPolicy, vector: dict) -> EscalationFinding | None:
    involved: list[str] = []
    granted_by: list[str] = []
    stmt_indexes: set[int] = set()
    passrole_stmts: list[Statement] = []
    other_stmts: list[Statement] = []

    for group in vector["required_groups"]:
        group_hit = False
        for action in group:
            stmts = granting_statements(policy, action)
            if action == "iam:PassRole":
                stmts = [s for s in stmts if _passrole_allows_services(s, vector.get("pass_to", []))]
                passrole_stmts.extend(stmts)
            elif vector.get("self_scoped_safe"):
                stmts = [s for s in stmts if not _is_self_scoped(s)]
            if not stmts:
                continue
            if action != "iam:PassRole":
                other_stmts.extend(stmts)
            group_hit = True
            involved.append(action)
            for s in stmts:
                stmt_indexes.add(s.index)
                for p in patterns_granting(s, action):
                    if p not in granted_by:
                        granted_by.append(p)
        if not group_hit:
            return None

    severity = vector["severity"]
    note = ""
    scoped_roles = _specific_roles(passrole_stmts)
    if scoped_roles:
        severity = "MEDIUM"
        note = (
            f"iam:PassRole is limited to {', '.join(scoped_roles)}. This is only an escalation if "
            "that role has more permissions than this identity -- review the role's policies."
        )
    elif (
        not passrole_stmts
        and other_stmts
        and all(is_specifically_scoped(s) for s in other_stmts)
        and not (vector.get("self_scope_dangerous") and any(_SELF_SCOPE in r for s in other_stmts for r in s.resources))
    ):
        severity = _LOWER.get(severity, severity)
        resources = sorted({r for s in other_stmts for r in s.resources})
        shown = ", ".join(resources[:3]) + (", ..." if len(resources) > 3 else "")
        note = (
            f"Limited to specific resources ({shown}). The risk depends on what those resources "
            "can do -- e.g. the permissions of the roles they run as."
        )

    involved_lower = {a.lower() for a in involved}
    return EscalationFinding(
        id=vector["id"],
        name=vector["name"],
        severity=severity,
        description=vector["description"],
        attack_path=vector["attack_path"],
        remediation=vector["remediation"],
        involved_actions=involved,
        statement_indexes=sorted(stmt_indexes),
        granted_by=[g for g in granted_by if g.lower() not in involved_lower],
        note=note,
    )


def _passrole_allows_services(stmt: Statement, services: list[str]) -> bool:
    """Apply iam:PassedToService conditions: can this statement pass a role to any of the services?"""
    if not services:
        return True
    allowed = set(services)
    for cond in stmt.conditions:
        if cond.key.lower() != "iam:passedtoservice":
            continue
        operator = cond.operator.split(":")[-1]
        if operator.endswith("IfExists"):
            operator = operator[: -len("IfExists")]
        values = [v.lower() for v in cond.values]
        matching = {svc for svc in allowed if any(fnmatchcase(svc, v) for v in values)}
        if operator in ("StringEquals", "StringLike", "StringEqualsIgnoreCase"):
            allowed = matching
        elif operator in ("StringNotEquals", "StringNotLike", "StringNotEqualsIgnoreCase"):
            allowed -= matching
    return bool(allowed)


def _is_self_scoped(stmt: Statement) -> bool:
    return bool(stmt.resources) and all(_SELF_SCOPE in r for r in stmt.resources)


def _specific_roles(passrole_stmts: list[Statement]) -> list[str]:
    """Role names if every PassRole grant targets explicitly named roles, else []."""
    if not passrole_stmts:
        return []
    roles: list[str] = []
    for stmt in passrole_stmts:
        if stmt.not_resources or not stmt.resources:
            return []
        for resource in stmt.resources:
            if ":role/" not in resource:
                return []
            name = resource.split(":role/", 1)[1]
            if "*" in name or "?" in name:
                return []  # a wildcard account ID is fine, a wildcard role name is not
            if name not in roles:
                roles.append(name)
    return roles
