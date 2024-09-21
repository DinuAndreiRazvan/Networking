# Server HTTP
## Descrierea programului
### client.cpp
Fisierul care contine programul principal. Se ocupa cu gestionarea
comenzilor primite de la utilizator si apelarea corespunzatoare a
functiilor care implementeaza creintele respective.
    Utilizatorul trebuie sa detina permisiuni pentru realizarea anumitor
comenzi, permisiuni care depind de variabilele
    - "cookie" -> se obtine in urma logarii utilizatorului si restrictio-
    neaza toate celelalte comenzi care privesc accesul librariei.
    - "token" -> se obtine in urma primirii accesului la librarie si
    restrictioneaza accesul la carti sau modificarea acestora

### commands.cpp
Implementeaza toate comenzile cerute (login, logout, enter_library,
get_books, get_book, add_book, delete_book) de care se va folosi client.cpp
pentru a indeplini cerintele utilizatorului.
    Parsarea formatului JSON am realizat-o cu ajutorul bibliotecii nlohmann
intrucat mi s-a parut ca are o documentatie bogata si un API simplu de folosit.
    Am verificat input-urile introduse de catre utilizator si apoi am trimis
un mesaj(construit in functie de tipul comenzii) catre server. Apoi primesc
raspunsul de la server si verific daca serinta s-a realizat cu succes, altfel
afisez un mesaj de eroare corespunzator.

### requests.cpp
Contine implementarea functiilor de constructie a mesajelor HTTP de tip
DELETE, GET sau POST. Toate trei au optiunea de adaugarea a cookie-urilor si
a unui token de autentificare. 

### connection.cpp
Prezinta functii care se ocupa de comunicarea client-server (deschiderea cone-
xiunii, trimiterea / primirea pachetelor si inchiderea canalului de comunicatie).
- buffer.cpp si buffer.h au rolul de suport in realizarea functiilor din
connection.cpp

### header.h
Tine informatii de legatura pentru toate fisierele, antetele functiilor
principale, constantele folosite si macro-ul de DIE.

