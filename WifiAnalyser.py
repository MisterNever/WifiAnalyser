from scapy.all import sniff, ARP, send

def detecter_intrusion(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): # Paquet ARP de requête ou de réponse
        print(f"Adresse IP : {pkt[ARP].psrc}, Adresse MAC : {pkt[ARP].hwsrc}")
        if est_paquet_dangereux(pkt):
            print("Paquet dangereux détecté ! Suppression...")
            supprimer_paquet(pkt)

def est_paquet_dangereux(pkt):
    # Ajoutez vos conditions pour détecter les paquets dangereux ici
    # Par exemple, vous pouvez vérifier une adresse IP ou une adresse MAC spécifique
    # Ici, nous supposons que les paquets provenant de l'adresse IP 192.168.1.100 sont dangereux
    return pkt[ARP].psrc == "192.168.1.100"

def supprimer_paquet(pkt):
    # Envoi d'une réponse ARP avec une adresse MAC invalide
    pkt_response = ARP(op=2, hwsrc="00:00:00:00:00:00", psrc=pkt[ARP].pdst, hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc)
    send(pkt_response, verbose=False)

if __name__ == "__main__":
    print("Démarrage de la détection d'intrusion...")
    sniff(filter="arp", prn=detecter_intrusion, store=0)
