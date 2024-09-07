#include "header.h"

void compute_message(char *message, const char *line)
{
    strcat(message, line);
    strcat(message, "\r\n");
}


char *compute_del_request(char *host, char *url, char *query_params,
                            char *cookies, int cookies_num,
                            char *authorization)
{
    char *message = (char*)calloc(BUFLEN, sizeof(char));
    char *line = (char*)calloc(LINELEN, sizeof(char));

    // Write the method name, URL, request params (if any) and protocol type
    if (query_params != NULL) {
        sprintf(line, "DELETE %s?%s HTTP/1.1", url, query_params);
    } else {
        sprintf(line, "DELETE %s HTTP/1.1", url);
    }

    compute_message(message, line);

    // Add the host
    if (host) {
        memset(line, 0, LINELEN);
        sprintf(line, "Host: %s", host);
        compute_message(message, line);
    }
    // (optional) Add headers and/or cookies, according to the protocol format
    if (cookies != NULL && cookies_num > 0) {
        memset(line, 0, LINELEN);
        sprintf(line, "Cookie: %s", cookies);
        compute_message(message, line);
    }
    // (optional) Add authorization
    if (authorization != NULL) {
        memset(line, 0, LINELEN);
        sprintf(line, "Authorization: Bearer %s", authorization);
        compute_message(message, line);
    }
    // Add final new line
    compute_message(message, "");
    free(line);

    return message;
}


char *compute_get_request(char *host, char *url, char *query_params,
                            char *cookies, int cookies_num,
                            char *authorization)
{
    char *message = (char*)calloc(BUFLEN, sizeof(char));
    char *line = (char*)calloc(LINELEN, sizeof(char));

    // Write the method name, URL, request params (if any) and protocol type
    if (query_params != NULL) {
        sprintf(line, "GET %s?%s HTTP/1.1", url, query_params);
    } else {
        sprintf(line, "GET %s HTTP/1.1", url);
    }

    compute_message(message, line);

    // Add the host
    if (host) {
        memset(line, 0, LINELEN);
        sprintf(line, "Host: %s", host);
        compute_message(message, line);
    }
    // (optional) Add headers and/or cookies, according to the protocol format
    if (cookies != NULL && cookies_num > 0) {
        memset(line, 0, LINELEN);
        sprintf(line, "Cookie: %s", cookies);
        compute_message(message, line);
    }
    // (optional) Add authorization
    if (authorization != NULL) {
        memset(line, 0, LINELEN);
        sprintf(line, "Authorization: Bearer %s", authorization);
        compute_message(message, line);
    }
    // Add final new line
    compute_message(message, "");
    free(line);

    return message;
}


char *compute_post_request(char *host, char *url, char* content_type, char *body_data,
                            int body_data_len, char *cookies, int cookies_len,
                            char *authorization)
{
    char *message = (char*)calloc(BUFLEN, sizeof(char));
    char *line = (char*)calloc(LINELEN, sizeof(char));

    // Write the method name, URL and protocol type
    sprintf(line, "POST %s HTTP/1.1", url);
    compute_message(message, line);
    
    // Add the host
    if (host) {
        sprintf(line, "Host: %s", host);
        compute_message(message, line);
    }
    /* Add necessary headers (Content-Type and Content-Length are mandatory)
            in order to write Content-Length you must first compute the message size
    */
    sprintf(line, "Content-Type: %s", content_type);
    compute_message(message, line);
    sprintf(line, "Content-Length: %d", body_data_len);
    compute_message(message, line);
    // (optional) Add cookies
    if (cookies != NULL && cookies_len > 0) {
        sprintf(line, "Cookie: %s", cookies);
        compute_message(message, line);
    }
    // (optional) Add authorization
    if (authorization != NULL) {
        memset(line, 0, LINELEN);
        sprintf(line, "Authorization: Bearer %s", authorization);
        compute_message(message, line);
    }
    // Add new line at end of header
    compute_message(message, "");
    compute_message(message, body_data);


    free(line);
    return message;
}