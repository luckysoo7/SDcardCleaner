@echo off
:: SD 카드 안전 삭제 도구 - 관리자 권한 런처
:: Python이 PATH에 등록되어 있어야 합니다 (python.org에서 설치 시 기본 등록)
::
:: 사용법: 이 .bat 파일을 더블클릭하면 UAC 프롬프트 후 프로그램 실행

powershell -Command "Start-Process python -ArgumentList '\"%~dp0sd_cleaner.py\"' -Verb RunAs -Wait"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [오류] 실행에 실패했습니다.
    echo Python이 설치되어 있는지 확인하세요: https://python.org
    echo.
    pause
)
