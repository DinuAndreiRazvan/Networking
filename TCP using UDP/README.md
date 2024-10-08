# Protocol TCP folosind UDP
## Implementare protocol peste UDP
### Three Way Handshake
In vederea realizarii conexiunii server-client am procedat astfel:
    - Clientul trimite SYN catre server
    - Serverul primeste mesajul SYN de la client, creeaza un socket
    nou si ii asociaza un port nou prin "bind". Serverul trimite
    SYN-ACK pentru a confirma ca a primit mesajul de la client si
    pentru a comunica noul port asociat(portul este trimis ca payload)
    - Clientul primeste confirmarea de la server,  actualizeaza portul
    si trimite ACK pentru a confirma server-ului ca a fost stabilita
    conexiunea
    - Server-ul primeste mesajul ACK de la client
Pentru trimiterea meajelor am utilizat headere de tip "poli_tcp_ctrl_hdr"
si instructiunile "sendto" si "recvfrom" se afla intr-o structura repeti-
tiva pentru a ma asigura ca ajung la destinatie.

### Protocolul Selective Repeat ARQ
Pentru trimiterea datelor am procedat astfel:
- Client
    Functia send_data:
        - Daca buffer depaseste lungimea maxima de payload, extrage din buffer
        MAX_DATA_SIZE bytes
        - Construieste un pachet cu un header de tip "poli_tcp_data_hdr" si cu
        datele din buffer si il adauga in segment_queue pentru a fi preluat si
        trimis de send_handler

    Functia sender_handler:
        - Trimite window_size pachete ca fereastra initiala (daca nu sunt sufi-
        ciente pachete in segment_queue asteapta ca send_data sa mai adauge
        pachete). Daca window_size este mai mare decat numarul total de pachete
        programul va cicla la infinit
        - Pachetele trimise sunt adaugate in window pentru a primii Ack (sunt
        adaugate specific unei cozi)
        - Daca este primit un Ack pentru un anumit pachet acesta este extras
        din window si este trimis urmatorul pachet din segment_queue (extragerea
        din window nu este conventionala unei cozi intrucat se pot pierde Ack-uri
        sau pot fi primite in ordine diferita)
        - Daca este primit un timeout retrimite primul pachet din window sau
        daca window este goala trimite o noua fereastra de pachete
        * Am ales sa implementez window de tip vector<char*> tocmai pentru a
        putea extrage elemente de oriunde din acesta, in funcie de ordinea de
        primire a ACK-urilor

    Functiile send_packet, send_init_window, send_slide_window si remove_ack_packet
    au fost realizate pentru o mai buna modularizare a codului. Acestea au un nume
    sugestiv si functionalitatea lor este explicata prin intermediul comentariilor.

- Server
    Functia recv_data:
        - Extrage din recv_packets pachete doar daca primul pachet din acesta
        are numarul de secventa asteptat

    Functia receiver_handler:
        - Daca este primit pachetul care era asteptat se adauga in recv_packets
        pentru a fi preluat de recv_data si se trimite ACK la client
        - Daca este primit un pachet cu un numar de secventa mai MARE decat cel
        asteptat se salveaza pachetul si se trimite ACK pentru acesta
        - Daca este primit un pachet cu un numar de secventa mai MIC decat cel
        asteptat inseamna ca ACK-ul nu a fost primit de catre client si se retri-
        mite un ACK pentru numarul de secventa respectiv
        * recv_packets este de tipul map<int, char*> pentru ca pachetele pot sa
        nu fie primite in ordine, sau sa nu fie primite deloc. Astfel pachetele
        primite sunt mereu in ordinea numarului de secventa al pachetului.
        * ACK- urile sunt pachete care au drept header "poli_tcp_ctrl_hdr" si au
        ca ack_num numarul de secventa al pachetului acceptat
    
    Analog functiilor auxiliare de la Client, functiile add_to_buffer si send_ack
    au rolul de a oferi modularizare codului. Acestea sunt explicate in comentarii.

De asemenea, am lasat instructiunile de afisare folosite in cazul in care se doreste
o inspectare mai atenta a protocolului.

### Au fost adaugate urmatoarele librarii din C++
- iostream
- math.h
- vector
- map


    
