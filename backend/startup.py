import shutil 
import os 
if os.path.exists("scamcheck_seed.db") and not os.path.exists("scamcheck.db"): 
    shutil.copy("scamcheck_seed.db", "scamcheck.db") 
    print("Copied seed database") 
else: 
    print("Database exists or no seed found") 
