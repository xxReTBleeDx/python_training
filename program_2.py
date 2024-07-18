import re


def validate_password(password):
    if len(password) < 8:
        return "Le mot de passe doit contenir au moins un chiffre"
    
    if not re.search(r'[A-Z]', password):
        return "Le mot de passe doit contenir au moins une majuscule"
    
    if not re.search(r'[a-z]', password):
        return "Le mot de passe doit contnir au moins une minuscule"
    
    if not re.search(r'[~!@#$%^&*()_+={}\[\]:;"\'<>,.?/\\|`]', password):
        return "Le mot de passe doit contneir au moins un caractere speciale"
    

    return "Bravo vous avez entre le bon mot de passe"


def demander():
    password = input("Entrez un mot de passe: ")
    return password

def main():
    password = demander()
    validate_result = validate_password(password)
    print(validate_result)

if __name__=='__main__':
    main()
