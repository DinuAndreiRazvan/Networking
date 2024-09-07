# DATAPLANE ROUTER

## PACKET QUEUE
* Structura **packet_cell** incapsuleaza informatiile necesare retinerii unui
packet pentru a fi trimis.
* Functia **build_packet_cell** construieste un element de tip "packet_cell*"
cu datele furnizate ca argumente
* Structura **Packet_Queue** reprezinta implementarea unei structuri de tip
coada pentru a retine pachetele primite de router.
* Functia **packet_queue_init** initializeaza o coada de tip "Packet_Queue*"
* Functia **packet_queue_empty** verifica daca o coada este goala
* Functia **enq_packet** adauga un element in coada
* Functia **deq_packet** extrage un element din coada
* Functia **find_packet** extrage din coada packetul care se potriveste cu
datele unui ARP-reply. Nu este specifica unei cozi, dar am ales aceasta
implementare in cazul in care mesajele de tip ARP-reply nu ajung in ordinea
in care ARP-request-urile au fost trimise.

## ROUTING TABLE
* Functia **get_best_route** implementeaza o cautare LPM liniara in tabela de
rutare 

## ARP PROTOCOL
* Functia **get_best_route** cauta adresa MAC a IP-ului primit ca argument in
tabela de adrese ARP (tabela completata dinamic in urma unei comunicatii cu
pachete de tip ARP)
* Functia **send_arp_req** trimite un ARP-request pentru a afla adresa MAC
asociata unei adrese IP

## ICMP PROTOCOL
* Functia **echo_icmp_reply** modifica pachetul primit pentru a fi retrimis ca
raspuns la un ICMP-echo-request
* Functia **build_icmp_err** construieste un mesaj de eroare de tip ICMP
(ICMP_TIME_EXCEEDED / ICMP_HOST_UNREACHABLE)

## MAIN
#### Aloca si initializaeaza variabilele globale.
### Loop-ul principal
1. Primeste un pachet
2. Extrage headerul de ethernet si verifica daca este destinat router-ului sau
daca este de tip broadcast, altfel nu il ia in considerare
3. Daca este destinat router-ului verifica tipul protocolului din payload-ul
ethernetului (*IPv4* / *ARP*).

    - In cazul *IPv4*:
        * Este verificata integritatea datelor prin **checksum**
        * Se actualizeaza **time to live** sau trimite *time exceeded* daca acesta
        este zero
        * Daca este un mesaj *ICMP-echo-request* catre router (ex: ping), modifica mesajul
        pentru a fi retrimis
        * Cauta cea mai buna ruta catre *IP*-ul destinatie si obtine adresa *IP* a
        urmatorului hop sau trimite *host ureachable* daca nu a gasit o ruta
        care sa se potriveasca
        * Recalculeaza *Checksum*
        * Cauta adresa *MAC* a urmatorului hop in tabela *ARP* sau trimite un mesaj *ARP-request*
        si adauga pachetul in coada pentru a fi trimis cand obtinem *ARP-reply*.
        * Modifica header-ul de ethernet si trimite pachetul final

    - In cazul *ARP*:
        * Daca este un *ARP-reply* la un request trimis de router, extrage adresa *MAC* din pachet,
        extrage pachetul initial din coada, schimba adresele *MAC* din header-ul de ethernet si
        trimite pachetul
        * Altfel pachetul nu se ia in considerare

6. Daca este de tip Broadcast si router-ul este destinatarul mesajului *ARP* incapsulat, modifica
pachetul cu adresa *MAC* proprie, prelucreaza header-ul *ARP* si ethernet si il retrimite.