@echo off
echo =======================================================
echo SECURE MUSIC COPYRIGHT ENCLAVE - SECURITY SCANNING
echo =======================================================

echo Installing security tools...
pip install bandit pylint safety --quiet

echo Running comprehensive security scans...
python run_security_scans.py

echo.
echo =======================================================
echo SCANNING COMPLETED!
echo =======================================================
echo Check the security_reports/ folder for all evidence files.
echo.
echo Files generated:
echo - bandit_report.txt (Bandit security analysis)
echo - bandit_report.html (HTML version)
echo - pylint_report.txt (Code quality analysis) 
echo - custom_security_report.txt (Custom security checks)
echo - dependency_report.txt (Dependency vulnerabilities)
echo - security_assessment_evidence.txt (Main evidence document)
echo.
echo Submit the entire security_reports/ folder with your assignment.

pause