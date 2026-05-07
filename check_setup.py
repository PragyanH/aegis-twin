"""
Aegis-Twin – Environment Verification Script
Run with: python check_setup.py
"""

import sys

packages = {
    "streamlit": "streamlit",
    "pandas": "pandas",
    "plotly": "plotly",
    "torch (PyTorch)": "torch",
    "scikit-learn": "sklearn",
    "scipy": "scipy",
    "shap": "shap",
}

print("=" * 55)
print("  Aegis-Twin Environment Check")
print("=" * 55)
print(f"  Python : {sys.version.split()[0]}")
print("-" * 55)

all_ok = True
for display_name, module_name in packages.items():
    try:
        mod = __import__(module_name)
        version = getattr(mod, "__version__", "unknown")
        print(f"  ✅  {display_name:<22} v{version}")
    except ImportError as e:
        print(f"  ❌  {display_name:<22} FAILED – {e}")
        all_ok = False

print("-" * 55)
if all_ok:
    print("  🎉  All packages imported successfully!")
else:
    print("  ⚠️  Some packages failed – check errors above.")
print("=" * 55)
