#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Универсальный скрипт для запуска всех тестов проекта.

Этот скрипт автоматически определяет, доступен ли pytest, и использует его.
Если pytest недоступен, запускает базовые тесты через run_tests.py.

Использование:
    python3 all_tests.py              # Запуск всех тестов
    python3 all_tests.py --no-cov     # Без покрытия (если pytest доступен)
    python3 all_tests.py --simple     # Только базовые тесты (run_tests.py)
"""

import sys
import subprocess
import os
from pathlib import Path


def check_pytest_available():
    """Проверяет, доступен ли pytest."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--version"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def run_pytest_tests(no_cov=False):
    """Запускает тесты через pytest."""
    cmd = [sys.executable, "-m", "pytest"]
    if no_cov:
        cmd.append("--no-cov")
    
    print("=" * 70)
    print("Запуск полного набора тестов через pytest...")
    print("=" * 70)
    print()
    
    result = subprocess.run(cmd)
    return result.returncode == 0


def run_simple_tests():
    """Запускает базовые тесты через run_tests.py."""
    script_path = Path(__file__).parent / "run_tests.py"
    
    if not script_path.exists():
        print(f"[ОШИБКА] Файл {script_path} не найден!")
        return False
    
    print("=" * 70)
    print("Запуск базовых тестов через run_tests.py...")
    print("=" * 70)
    print()
    
    result = subprocess.run([sys.executable, str(script_path)])
    return result.returncode == 0


def main():
    """Главная функция."""
    args = sys.argv[1:]
    simple_mode = "--simple" in args
    no_cov = "--no-cov" in args
    
    # Если явно запрошен простой режим
    if simple_mode:
        success = run_simple_tests()
        sys.exit(0 if success else 1)
    
    # Проверяем доступность pytest
    if check_pytest_available():
        print("[INFO] pytest доступен, запускаем полный набор тестов")
        print()
        success = run_pytest_tests(no_cov=no_cov)
        sys.exit(0 if success else 1)
    else:
        print("[WARNING] pytest не найден в системе!")
        print("[INFO] Установите pytest для полного набора тестов:")
        print("       pip install -r requirements.txt")
        print()
        print("[INFO] Запускаем базовые тесты через run_tests.py...")
        print()
        success = run_simple_tests()
        
        if success:
            print()
            print("=" * 70)
            print("[INFO] Базовые тесты прошли успешно!")
            print("[INFO] Для полного набора тестов установите pytest:")
            print("       pip install -r requirements.txt")
            print("       python3 -m pytest")
            print("=" * 70)
        
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

