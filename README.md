
DevSecOps workflow description
==============================

For purpose of this technical assignement we use DVPWA app. DVPWA is an intentionally vulnerable application. 
This repo is a clone of [DVPWA](https://github.com/anxolerd/dvpwa) and is used for devsecops workflow technical challenges.


For **SAST** and **SCA** analysis of the code, we use [Horusec](https://horusec.io/) open-source tool. In this case, we use only CLI, which is not integrated with [web UI](https://docs.horusec.io/docs/web/overview/) of Horusec. 
The results of the analysis are in the logs of workflow. 
Workflow is defined in [workflow file](https://github.com/GoranP/dvpwa/blob/master/.github/workflows/horusec.yaml) 
Workflow has two steps/jobs invoked upon merging or committing to a master or triage branch.

* The first step (_horusec-security_) is **SAST** and **SCA**  analysis of the code, 
* The second step (_build-secure-images_) is building docker images and pushing them to the public docker repository.

The second job depends on the first, and if the first job finds any vulnerabilities, the build pipeline will break.

Analysis results
================
Initial analysis of the code found 25 vulnerabilities visible in the logs:

```code
In this analysis, a total of 25 possible vulnerabilities were found, and we classified them into:

Total of Vulnerability LOW is: 1
Total of Vulnerability CRITICAL is: 2
Total of Vulnerability HIGH is: 18
Total of Vulnerability MEDIUM is: 4
```

Detailed logs are visible in [workflow logs](https://github.com/GoranP/dvpwa/runs/7111064002?check_suite_focus=true).

For demonstration, two CRITICAL, two HIGH, one MEDIUM and one LOW issues are fixed, and all others are accepted.
All fixes are visible in [triage](https://github.com/GoranP/dvpwa/tree/triage) branch.

Comments about fixes are visible in [PR](https://github.com/GoranP/dvpwa/pull/1)


Vulnerabilities found in `master` and fixed in `triage` branch.
===============================================================

The following critical issues are fixed by increasing the version of the library:

```code
Language: Generic
Severity: CRITICAL
Line: 15
Column: 0
SecurityTool: Trivy
Confidence: MEDIUM
File: /home/runner/work/dvpwa/dvpwa/requirements.txt
Code: pyyaml==3.13
  Installed Version: "3.13"
  Update to Version: "5.1" for fix this issue.
RuleID: CVE-2017-18342
Type: Vulnerability
Commit Author: GoranP
Commit Date: 2022-06-23 10:19:11 +0200
Commit Email: goran.pizent@protonmail.com
Commit CommitHash: 5173722956906204c265e871895854606d256067
Commit Message: init commit
ReferenceHash: 14833ddff622c5a7a2b7bdcd7ca8c09c1d54c1dba2231bc114118a500f1d6182
Details: (1/1) * Possible vulnerability detected: In PyYAML before 5.1, the yaml.load() API could execute arbitrary code if used with untrusted data. The load() function has been deprecated in version 5.1 and the 'UnsafeLoader' has been introduced for backward compatibility with the function.
PrimaryURL: https://avd.aquasec.com/nvd/cve-2017-18342.
Cwe Links: (https://cwe.mitre.org/data/definitions/502.html)
==================================================================================

Language: Generic
Severity: CRITICAL
Line: 15
Column: 0
SecurityTool: Trivy
Confidence: MEDIUM
File: /home/runner/work/dvpwa/dvpwa/requirements.txt
Code: pyyaml==3.13
  Installed Version: "3.13"
  Update to Version: "5.4" for fix this issue.
RuleID: CVE-2020-14343
Type: Vulnerability
Commit Author: GoranP
Commit Date: 2022-06-23 10:19:11 +0200
Commit Email: goran.pizent@protonmail.com
Commit CommitHash: 5173722956906204c265e871895854606d256067
Commit Message: init commit
ReferenceHash: 69677e7e8ba5023bce09e3fdf3ba2dfb7393aad481f246ace0384f5fe2c55f04
Details: (1/1) * Possible vulnerability detected: A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is susceptible to arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader. Applications that use the library to process untrusted input may be vulnerable to this flaw. This flaw allows an attacker to execute arbitrary code on the system by abusing the python/object/new constructor. This flaw is due to an incomplete fix for CVE-2020-1747.
PrimaryURL: https://avd.aquasec.com/nvd/cve-2020-14343.
Cwe Links: (https://cwe.mitre.org/data/definitions/20.html)
==================================================================================

```



Following MEDIUM issue is fixed in the code:

```code
==================================================================================
Language: Python
Severity: MEDIUM
Line: 42
Column: 0
SecurityTool: Bandit
Confidence: LOW
File: /home/runner/work/dvpwa/dvpwa/sqli/dao/student.py
Code: 41     async def create(conn: Connection, name: str):
42         q = ("INSERT INTO students (name) "
RuleID: B608
Type: Vulnerability
Commit Author: GoranP
Commit Date: 2022-06-23 10:19:11 +0200
Commit Email: goran.pizent@protonmail.com
Commit CommitHash: 5173722956906204c265e871895854606d256067
Commit Message: init commit
ReferenceHash: 767c1fc313c2d47cf1d4c4ea9d74d3bbd6cf27789a0592c9c8b0615e2d0eb2f7
Details: (1/1) * Possible vulnerability detected: Possible SQL injection vector through string-based query construction.
=================================================================================
```


Following HIGH and LOW issues are fixed regarding insecure Dockerfile:

```code
==================================================================================
Language: Generic
Severity: HIGH
Line: 0
Column: 0
SecurityTool: Trivy
Confidence: MEDIUM
File: /home/runner/work/dvpwa/dvpwa/Dockerfile.app
Code: root user
Type: Vulnerability
Commit Author: GoranP
Commit Date: 2022-06-23 10:19:11 +0200
Commit Email: goran.pizent@protonmail.com
Commit CommitHash: 5173722956906204c265e871895854606d256067
Commit Message: init commit
ReferenceHash: 8251e136da9e4ffa49be7d64a4a722e9c65304a87318a1106c6e5a4c60a35a14
Details: (1/1) * Possible vulnerability detected: MissConfiguration
      Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.
      Message: Specify at least 1 USER command in Dockerfile with non-root user as argument
      Resolution: Add 'USER <non root user name>' line to the Dockerfile
      References: [https://docs.docker.com/develop/develop-images/dockerfile_best-practices/ https://avd.aquasec.com/appshield/ds002
==================================================================================
Language: Generic
Severity: HIGH
Line: 0
Column: 0
SecurityTool: Trivy
Confidence: MEDIUM
File: /home/runner/work/dvpwa/dvpwa/Dockerfile.db
Code: root user
Type: Vulnerability
Commit Author: GoranP
Commit Date: 2022-06-23 10:19:11 +0200
Commit Email: goran.pizent@protonmail.com
Commit CommitHash: 5173722956906204c265e871895854606d256067
Commit Message: init commit
ReferenceHash: 91e5e13c5059cc6c7471e68c4b34a900fcb01b7ca434c44e9214fe88824a273e
Details: (1/1) * Possible vulnerability detected: MissConfiguration
      Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.
      Message: Specify at least 1 USER command in Dockerfile with non-root user as argument
      Resolution: Add 'USER <non root user name>' line to the Dockerfile
      References: [https://docs.docker.com/develop/develop-images/dockerfile_best-practices/ https://avd.aquasec.com/appshield/ds002
==================================================================================

==================================================================================
Language: Generic
Severity: LOW
Line: 0
Column: 0
SecurityTool: Trivy
Confidence: MEDIUM
File: /home/runner/work/dvpwa/dvpwa/Dockerfile.app
Code: ADD instead of COPY
Type: Vulnerability
Commit Author: GoranP
Commit Date: 2022-06-23 10:19:11 +0200
Commit Email: goran.pizent@protonmail.com
Commit CommitHash: 5173722956906204c265e871895854606d256067
Commit Message: init commit
ReferenceHash: 3af46c44415204250a44c06dd7aeb0ed96d6d5889376bae08170e6da6f362974
Details: (1/3) * Possible vulnerability detected: MissConfiguration
      You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.
      Message: Consider using 'COPY ./config /app/config' command instead of 'ADD ./config /app/config'
      Resolution: Use COPY instead of ADD
      References: [https://docs.docker.com/engine/reference/builder/#add https://avd.aquasec.com/appshield/ds005
(2/3) * Possible vulnerability detected: MissConfiguration
      You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.
      Message: Consider using 'COPY ./run.py /app' command instead of 'ADD ./run.py /app'
      Resolution: Use COPY instead of ADD
      References: [https://docs.docker.com/engine/reference/builder/#add https://avd.aquasec.com/appshield/ds005
(3/3) * Possible vulnerability detected: MissConfiguration
      You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.
      Message: Consider using 'COPY ./sqli /app/sqli' command instead of 'ADD ./sqli /app/sqli'
      Resolution: Use COPY instead of ADD
      References: [https://docs.docker.com/engine/reference/builder/#add https://avd.aquasec.com/appshield/ds005
==================================================================================

```

