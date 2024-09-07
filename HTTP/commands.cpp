#include <iostream>
#include <nlohmann/json.hpp>
#include "header.h"

using string = std::string;
using json = nlohmann::json;

// Converts username and password to json format
char *to_json_str(char *username, char *password) {
    char *str = (char*)calloc(200 ,sizeof(char));

    sprintf(str, "{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
    return str;
}

// Converts the content of a char[] to int 
int str_to_int(char *str) {
    int res = 0, i = 0;
    char c = str[i];
    while (c >= '0' && c <= '9' && i < (int)strlen(str)) {
        res = res*10 + (c - '0');
        c = str[++i];
    }
    return res;
}


// Extracts the payload from a message received from server
char *extract_payload(char *response) {
    int len = 0;
    char *str = strstr(response, "Content-Length: ");
    if (str == NULL)
        return NULL;
    str += strlen("Content-Length: ");

    /* Get the size of the payload */
    len = str_to_int(str);

    /* Extract the payload */
    char *payload = (char*)calloc(len, sizeof(char));
    memcpy(payload, response + strlen(response) - len, len);

    return payload;
}

// Checks for errors reported by server in payload
void error_msg_payload(char *payload) {
    /* Check for errors */
    if (payload != NULL && strstr(payload, "error") != 0) {
        /* Convert to json */
        string str(payload);
        json j = json::parse(str);
        std::cerr << " ERROR -" << j["error"] << "\n";
    } else {
        std::cerr << "No message in payload\n";
    }
}


// Extracts the cookie from a message received from server
char *extract_cookie(char *response) {
    char *str = strstr(response, "Cookie: ");
    if (str == NULL) {
        std::cerr << "No Cookie field\n";
        return NULL;
    }
    str += strlen("Cookie: ");


    /* Extract the cookie */
    char *c = strtok(str, "\r\n");
    char *cookie = (char*)calloc(200, sizeof(char));
    memcpy(cookie, c, strlen(c));

    return cookie;
}


int check_response(char *response) {
    char *p = response;
    while (p[0] != ' ')
        p++;
    p++;

    int code = str_to_int(p);
    std::cout << "Received code - " << code << " - ";
    switch (code)
    {
    case 200:
        std::cout << "OK\n";
        break;
    case 201:
        std::cout << "Created - OK\n";
        break;
    case 204:
        std::cout << "No Content\n";
        break;
    case 400:
        std::cout << "BAD Request\n";
        break;
    case 401:
        std::cout << "Unauthorized\n";
        break;
    case 403:
        std::cout << "Forbidden\n";
        break;
    case 404:
        std::cout << "Resource Not Found\n";
        break;
    case 500:
        std::cout << "Internal Server Error\n";
        break;
    default:
        std::cout << "\n";
        break;
    }
    return code;
}


/* --------------------- REGISTER --------------------- */
void register_user() {
    char username[50], password[50];
    char *payload, *message, *response;

    /* Read input */
    getc(stdin); // left newline
    std::cout << "username=";
    fgets(username, 50, stdin);
    username[strlen(username)-1] = '\0';
    std::cout << "password=";
    fgets(password, 50, stdin);
    password[strlen(password)-1] = '\0';

    if (strlen(username) == 0 || strlen(password) == 0) {
        std::cout << "ERROR - Invalid input format\n";
        return;
    }

    for (int i = 0; i < (int)strlen(username); i++) {
        if (!((username[i] >= '0' && username[i] <= '9') ||
            (username[i] >= 'a' && username[i] <= 'z') ||
            (username[i] >= 'A' && username[i] <= 'Z'))) {
            std::cout << "ERROR - Invalid username format\n";
            return;
        }
    }

    /* Build payload */
    payload = to_json_str(username, password);
    /* Send message */
    int sockfd = open_connection(HOST_IP, 8080, AF_INET, SOCK_STREAM, 0);
    message = compute_post_request(HOST_IP, REGISTER_URL,
                CONTENT_TYPE, payload, strlen(payload), NULL, 0, NULL);
    send_to_server(sockfd, message);
    /* Receive from server */
    response = receive_from_server(sockfd);
    close_connection(sockfd);

    /* Check the response */
    if (check_response(response) != 200) {
        char *p = extract_payload(response);
        error_msg_payload(p);
        free(p);
    }

    free(payload);
    free(message);
    free(response);
    std::cout << "\n";
}


/* --------------------- LOGIN --------------------- */
char *login() {
    char username[50], password[50];
    char *payload, *message, *response;

    /* Read input */
    getc(stdin); // left newline
    std::cout << "username=";
    fgets(username, 50, stdin);
    username[strlen(username)-1] = '\0';
    std::cout << "password=";
    fgets(password, 50, stdin);
    password[strlen(password)-1] = '\0';

    /* Build payload */
    payload = to_json_str(username, password);
    /* Send message */
    int sockfd = open_connection(HOST_IP, 8080, AF_INET, SOCK_STREAM, 0);
    message = compute_post_request(HOST_IP, LOGIN_URL,
                CONTENT_TYPE, payload, strlen(payload), NULL, 0, NULL);
    send_to_server(sockfd, message);
    /* Receive from server */
    response = receive_from_server(sockfd);
    close_connection(sockfd);


    /* Check the response */
    char *cookie;
    if(check_response(response) == 200) {
        cookie = extract_cookie(response);
        //std::cout << "Cookie: " << cookie << "\n";
    } else {
        cookie = NULL;
        char *p = extract_payload(response);
        error_msg_payload(p);
        free(p);
    }

    free(payload);
    free(message);
    free(response);
    std::cout << "\n";

    return cookie;
}


/* --------------------- LIBRARY ACCES REQUEST-------------------- */
char *enter_library(char *cookie) {
    char *message, *response, *token = NULL;

    if (cookie == NULL) {
        std::cerr << "Cookie is invalid (NULL) - Please Login first\n\n";
        return NULL;
    }

    /* Send message */
    int sockfd = open_connection(HOST_IP, 8080, AF_INET, SOCK_STREAM, 0);
    message = compute_get_request(HOST_IP, ENTER_LIB_URL, NULL, cookie, 1, NULL);
    send_to_server(sockfd, message);
    /* Receive from server */
    response = receive_from_server(sockfd);
    close_connection(sockfd);

    /* Check the response */
    if(check_response(response) == 200) {
        char *payload;
        payload = extract_payload(response);
        
        string str(payload);
        json j = json::parse(str);
        string tk = j["token"];
        char *tk_ptr = (char*)tk.c_str();
        token = (char*)calloc(tk.size(), sizeof(char));
        memcpy(token, tk_ptr, tk.size());
        free(payload);

        std::cout << "-- SUCCESS --\n";
    } else {
        char *p = extract_payload(response);
        error_msg_payload(p);
        free(p);
    }

    free(message);
    free(response);
    std::cout << "\n";

    return token;
}


/* --------------------- GET BOOKS -------------------- */
void get_books(char *cookie, char *token) {
    char *message, *response;

    /* Check Args */
    if (cookie == NULL) {
        std::cerr << "Cookie is invalid (NULL) - Please Login first\n\n";
        return;
    }
    if (token == NULL) {
        std::cerr << "Token is invalid (NULL)";
        std::cerr << " - Please Get Library Acces permision\n\n";
        return;
    }

    /* Send message */
    int sockfd = open_connection(HOST_IP, 8080, AF_INET, SOCK_STREAM, 0);
    message = compute_get_request(HOST_IP, BOOKS_URL, NULL, cookie, 1, token);
    send_to_server(sockfd, message);
    /* Receive from server */
    response = receive_from_server(sockfd);
    close_connection(sockfd);

    /* Check the response */
    if(check_response(response) == 200) {
        char *p = extract_payload(response);
        /* Remove extras */
        int i = strlen(p)-1;
        while (p[i] != ']')
            i--;
        p[i+1]='\0';
        /* Convert to JSON */
        string str(p);
        json j = json::parse(str);
        string output = j.dump(4);
        std::cout << output << "\n";
        std::cout << "-- SUCCESS --\n";
        free(p);
    } else {
        char *p = extract_payload(response);
        error_msg_payload(p);
        free(p);
    }

    free(message);
    free(response);
    std::cout << "\n";
}


/* --------------------- GET BOOK -------------------- */
void get_book(char *cookie, char *token) {
    char ID[10], url[100];
    char *message, *response;

    /* Check Args */
    if (cookie == NULL) {
        std::cerr << "Cookie is invalid (NULL) - Please Login first\n\n";
        return;
    }
    if (token == NULL) {
        std::cerr << "Token is invalid (NULL)";
        std::cerr << " - Please Get Library Acces permision\n\n";
        return;
    }

    /* Get input from user */
    std::cout << "id=";
    std::cin >> ID;
    int id = str_to_int(ID);
    std::cout << "id = " << id << "\n";


    strcpy(url, BOOKS_URL);
    strcat(url, "/");
    strcat(url, ID);
    std::cout << "URL: " << url << "\n";
    /* Send message */
    int sockfd = open_connection(HOST_IP, 8080, AF_INET, SOCK_STREAM, 0);
    message = compute_get_request(HOST_IP, url, NULL, cookie, 1, token);
    send_to_server(sockfd, message);
    /* Receive from server */
    response = receive_from_server(sockfd);
    close_connection(sockfd);

    /* Check the response */
    if(check_response(response) == 200) {
        char *p = extract_payload(response);
        std::cout << "Payload: " << p << "\n";
        string str(p);
        json j = json::parse(str);
        std::cout << j << "\n";
        std::cout << "-- SUCCESS --\n";
        free(p);
    } else {
        char *p = extract_payload(response);
        error_msg_payload(p);
        free(p);
    }

    free(message);
    free(response);
    std::cout << "\n";
}

/* --------------------- ADD BOOK -------------------- */
void add_book(char *cookie, char *token) {
    char title[100], author[100], genre[100], publisher[100], page_count[100];
    char *message, *response, *payload;

    /* Check Args */
    if (cookie == NULL) {
        std::cerr << "Cookie is invalid (NULL) - Please Login first\n\n";
        return;
    }
    if (token == NULL) {
        std::cerr << "Token is invalid (NULL)";
        std::cerr << " - Please Get Library Acces permision\n\n";
        return;
    }

    /* Get input from user */
    getc(stdin); // left newline
    std::cout << "title=";
    fgets(title, 100, stdin);
    title[strlen(title)-1] = '\0';

    std::cout << "author=";
    fgets(author, 100, stdin);
    author[strlen(author)-1] = '\0';

    std::cout << "genre=";
    fgets(genre, 100, stdin);
    genre[strlen(genre)-1] = '\0';

    std::cout << "publisher=";
    fgets(publisher, 100, stdin);
    publisher[strlen(publisher)-1] = '\0';

    std::cout << "page_count=";
    fgets(page_count, 100, stdin);
    page_count[strlen(page_count)-1] = '\0';

    /* Check page count */
    if (strlen(title) == 0 || strlen(author) == 0 || strlen(genre) == 0
        || strlen(publisher) == 0 || strlen(page_count) == 0) {
        std::cout << "ERROR - Tip de date incorect pentru numarul de pagini\n";
        return;
    }
    if (strlen(page_count) > 9) {
        std::cout << "ERROR - Tip de date incorect pentru numarul de pagini\n";
        return;
    }
    int pg = 0, i = 0;
    char c = page_count[i];
    while (c >= '0' && c <= '9' && i < (int)strlen(page_count)) {
        pg = pg*10 + (c - '0');
        c = page_count[++i];
    }
    if (i != (int)strlen(page_count)) {
        std::cout << "Tip de date incorect pentru numarul de pagini\n";
        return;
    }

    /* Build JSON payload */
    json j;
    j["title"] = title;
    j["author"] = author;
    j["genre"] = genre;
    j["publisher"] = publisher;
    j["page_count"] = pg;

    string str = j.dump();
    payload = (char*)str.c_str();

    /* Send message */
    int sockfd = open_connection(HOST_IP, 8080, AF_INET, SOCK_STREAM, 0);
    message = compute_post_request(HOST_IP, BOOKS_URL,
                CONTENT_TYPE, payload, strlen(payload), cookie, 1, token);
    send_to_server(sockfd, message);
    /* Receive from server */
    response = receive_from_server(sockfd);
    close_connection(sockfd);

    /* Check the response */
    if(check_response(response) == 200) {
        char *p = extract_payload(response);
        std::cout << "Payload: " << p << "\n";
        std::cout << "-- SUCCESS --\n";
        free(p);
    } else {
        char *p = extract_payload(response);
        error_msg_payload(p);
        free(p);
    }

    free(message);
    free(response);
    std::cout << "\n";
}


/* --------------------- DELETE BOOK -------------------- */
void delete_book(char *cookie, char *token) {
    char ID[10], url[100];
    char *message, *response;

    /* Check Args */
    if (cookie == NULL) {
        std::cerr << "Cookie is invalid (NULL) - Please Login first\n\n";
        return;
    }
    if (token == NULL) {
        std::cerr << "Token is invalid (NULL)";
        std::cerr << " - Please Get Library Acces permision\n\n";
        return;
    }

    /* Get input from user */
    std::cout << "id=";
    std::cin >> ID;
    int id = str_to_int(ID);
    std::cout << "id = " << id << "\n";

    /* Complete url */
    strcpy(url, BOOKS_URL);
    strcat(url, "/");
    strcat(url, ID);
    std::cout << "URL: " << url << "\n";

    /* Send message */
    int sockfd = open_connection(HOST_IP, 8080, AF_INET, SOCK_STREAM, 0);
    message = compute_del_request(HOST_IP, url, NULL, cookie, 1, token);
    send_to_server(sockfd, message);
    /* Receive from server */
    response = receive_from_server(sockfd);
    close_connection(sockfd);

    /* Check the response */
    if(check_response(response) == 200) {
        char *p = extract_payload(response);
        std::cout << "Payload: " << p << "\n";
        std::cout << "-- SUCCESS --\n";
        free(p);
    } else {
        char *p = extract_payload(response);
        error_msg_payload(p);
        free(p);
    }

    free(message);
    free(response);
    std::cout << "\n";
}


/* --------------------- LOGOUT -------------------- */
void logout(char *cookie) {
    char *message, *response;

    /* Check Args */
    if (cookie == NULL) {
        std::cerr << "Cookie is invalid (NULL) - Please Login first\n\n";
        return;
    }

    /* Send message */
    int sockfd = open_connection(HOST_IP, 8080, AF_INET, SOCK_STREAM, 0);
    message = compute_get_request(HOST_IP, LOGOUT_URL, NULL, cookie, 1, NULL);
    send_to_server(sockfd, message);
    /* Receive from server */
    response = receive_from_server(sockfd);
    close_connection(sockfd);

    /* Check the response */
    if(check_response(response) == 200) {
        char *p = extract_payload(response);
        std::cout << "Payload: " << p << "\n";
        std::cout << "-- SUCCESS --\n";
        free(p);
    } else {
        char *p = extract_payload(response);
        error_msg_payload(p);
        free(p);
    }

    free(message);
    free(response);
    std::cout << "\n";
}