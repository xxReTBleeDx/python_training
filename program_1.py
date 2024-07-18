import time

'''def choix():

    n = int(input("Entrez un chiffre: "))

    if n == 0:
        print("Choix invalide. Veuillez ressayer")
        KeyboardInterrupt
    else:
        for i in reversed(range(n)):
            print(f"COUNTDOWN: {i:02}", end='\r')
            time.sleep(1)
'''

def choix():
    n = int(input("Entrez un chiffre pour fibonacci "))
    return n
    

def fibo():
    n = choix()
    a, b = 0, 1
    count = 0
    for _ in range(n):
        print(a, flush=True)
        a, b = b, a + b
        time.sleep(1)
        
        count += 1


fibo()