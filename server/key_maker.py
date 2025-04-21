#=== Computer Science Non-Exam-Assessment A Level ===#
#=== Server Program Encryption Key Creator ===#

#=== Creates Database Encryption Key ===#
#=== Run this program once before running the main program ===#

#=== Import relevant Modules ===#
from cryptography.fernet import Fernet

#=== Create Key ===#
def create_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

#=== Run as Main Function ===#
if __name__ == "__main__":
    create_key()