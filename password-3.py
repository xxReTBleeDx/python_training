import re 


def validate_length(password):
    if len(password):
        return "Le mot de passe doit contenir au moins 8 caracteres"
    return ""

def validate_digits(password):
    if not re.search(r'[\d]', password):
        return "Le mot de passe coit contenir au moins un chiffre"
    return ""

def validate_upper(password):
    if not re.search(r'[A-Z]', password):
        return "Le mot de passe doit contenir au moins une MAJUSCULE"
    return ""

def validate_lower(password):
    if not re.search(r'[a-z]', password):
        return "Le mot de passe doit contenir au mons une minuscule"
    return ""

def validate_special_char(password):
    if not re.search(r'[!@#$%^&*?-_]', password):
        return "Le mot de passe doit contenir au moins un charactere speciale"
    return ""

def demander():
    password = input("Entrez un mot de passe securisee: > ")
    return password

def main():
    password = demander()
    validators = [
        validate_length,
        validate_digits,
        validate_upper,
        validate_lower,
        validate_special_char
    ]

    missing_criter = []

    for validator in validators:
        result = validator(password)
        if result:
            missing_criter.append(result)
    if missing_criter:
        for criter in missing_criter:
            print(criter)
    else:
        print("vous avez entree un mot de passe fort")

if __name__=='__main__':
    main()
