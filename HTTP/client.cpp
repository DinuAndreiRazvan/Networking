#include <iostream>
#include "header.h"

using namespace std;

int main() {
    char input[100], *cookie = NULL, *token = NULL;
   
    while (1) {
            cin >> input;

            if (strcmp(input, "register") == 0) {
                register_user();

            } else if (strcmp(input, "login") == 0) {
                if (cookie != NULL)
                    free(cookie);
                cookie = login();
            } else if (strcmp(input, "enter_library") == 0) {
                if (token != NULL)
                    free(token);
                token = enter_library(cookie);
            } else if (strcmp(input, "get_books") == 0) {
                get_books(cookie, token);
            } else if (strcmp(input, "get_book") == 0) {
                get_book(cookie, token);
            } else if (strcmp(input, "add_book") == 0) {
                add_book(cookie, token);
            } else if (strcmp(input, "delete_book") == 0) {
                delete_book(cookie, token);
            } else if (strcmp(input, "logout") == 0) {
                logout(cookie);
            } else if (strcmp(input, "exit") == 0) {
                break;
            } else {
                cout << "Functionality Not implemented\n\n";
            }
    }

    if (cookie != NULL)
        free(cookie);
    if (token != NULL)
        free(token);
    return 0;
}