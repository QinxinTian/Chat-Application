#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>
#include <map>
#include <algorithm>

#include "../include/global.h"
#include "../include/logger.h"

using namespace std;

typedef struct Client
{
    char hostname[HOSTNAME_LEN];
    struct in_addr ip;
    int port;
} Client;

typedef enum
{
    LOGIN,
    RESPONSE,
    LIST,
    MESSAGE,
    BLOCK,
    UNBLOCK,
    REFRESH,
    LOGOUT,
    BROADCAST,
    EXIT,
    SENDFILE
} MessageType;

typedef enum
{
    Login, Logout, Exit, NotLogin
} Status;
const char* StatusNames[] = { "logged-in", "logged-out", "logged-out",
        "not logged-in" };

typedef struct
{
    int from;
    int to;
    char message[256];
} Message;

typedef struct Header
{
    MessageType type;
    int datasize;
} Header;

typedef struct
{
    int port;
    int send;
    int recv;
    Status status;
    vector<int> blocks;
    vector<Message> buffer;
} Information;

//typedef struct Block
//{
//    int from;
//    int to;
//} Block;

vector<Client> clients;
map<int, Information> infos;
bool serverMode = false;
int serverip = 0;
int serverport;
bool loggedin = false;

bool validate_ip(const char* s)
{
    int number = 0;
    int dot_count = 0;
    while (*s)
    {
        if (*s == '.')
        {
            dot_count++;
            if (dot_count > 3)
            {
                return 0;
            }
            if (number >= 0 && number <= 255)
            {
                number = 0;
            }
            else
            {
                return false;
            }
        }
        else if (*s >= '0' && *s <= '9')
        {
            number = number * 10 + *s - '0';
        }
        else
        {
            return false;
        }
        s++;
    }

    if (number >= 0 && number <= 255)
    {
        if (dot_count < 3)
        {
            return false;
        }
    }
    return true;
}

bool validate_port(const char* p)
{
    const char* s = p;
    while (*s)
    {
        if (*s < '0' || *s > '9')
        {
            return false;
        }
        s++;
    }
    int port = atoi(p);
    if (port == 0 || port > 65535)
    {
        return false;
    }
    return true;
}

bool sort_by_port(const Client& obj1, const Client& obj2)
{
    return obj1.port < obj2.port;
}

void sendData(int ip, int port, const char* data, int size)
{
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = ip;
    bzero(&(serv_addr.sin_zero), 8);
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        cout << "create socket error" << endl;
        exit(1);
    }
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr))
            < 0)
    {
        cout << "connect error" << endl;
        return;
    }
    send(sockfd, data, size, 0);
    close(sockfd);
}

void sendList(int ip, int port)
{
    Header header;
    header.type = LIST;
    header.datasize = clients.size();
    char* data = new char[sizeof(Header) + sizeof(Client) * clients.size()];
    memcpy(data, &header, sizeof(header));
    memcpy(data + sizeof(header), &clients[0], sizeof(Client) * clients.size());
    sendData(ip, port, data, sizeof(Header) + sizeof(Client) * clients.size());
}

void sendMessageToClient(int ip, int port, Message& msg)
{
    char* data = new char[sizeof(Header) + sizeof(Message)];
    Header h;
    h.type = MESSAGE;
    h.datasize = sizeof(Message);
    memcpy(data, &h, sizeof(h));
    memcpy(data + sizeof(h), &msg, sizeof(msg));
    sendData(ip, port, data, sizeof(Header) + sizeof(Message));
    delete[] data;
    in_addr from;
    from.s_addr = msg.from;
    in_addr to;
    to.s_addr = msg.to;

    cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
    char fromip[16];
    strcpy(fromip, inet_ntoa(from));
    cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", fromip,
            inet_ntoa(to), msg.message);
    cse4589_print_and_log("[%s:END]\n", "RELAYED");
}

bool isBlocked(int from, vector<int>& list)
{
    for (size_t i = 0; i < list.size(); i++)
    {
        if (from == list[i] || list[i] == -1)
        {
            return true;
        }
    }
    return false;
}

void sendBufferedMessage(int ip, int port)
{
    Information& info = infos[ip];
    for (size_t i = 0; i < info.buffer.size(); i++)
    {
        sendMessageToClient(ip, port, info.buffer[i]);
    }
    info.recv += info.buffer.size();
    info.buffer.clear();
}

void recvData(int socket_fd)
{
    int new_socket_fd;
    socklen_t addr_length;
    struct sockaddr_in client_addr;
    addr_length = sizeof(client_addr);
    new_socket_fd = accept(socket_fd, (struct sockaddr *) &client_addr,
            &addr_length);
    if (new_socket_fd < 0)
    {
        cout << "accept error" << endl;
        exit(1);
    }
    Header header;
    read(new_socket_fd, &header, sizeof(header));
    switch (header.type)
    {
    case LOGIN:
    {
//        cout << "recv login from " << inet_ntoa(client_addr.sin_addr) << endl;
        Client client;
        client.ip = client_addr.sin_addr;
        read(new_socket_fd, client.hostname, HOSTNAME_LEN);
        read(new_socket_fd, &client.port, sizeof(client.port));
        size_t i;
        for (i = 0; i < clients.size(); i++)
        {
            if (clients[i].ip.s_addr == client.ip.s_addr)
            {
                clients[i] = client;
                break;
            }
        }
        if (i == clients.size())
        {
            clients.push_back(client);
        }
        if (infos.find(client.ip.s_addr) == infos.end())
        {
            Information info;
            info.port = client.port;
            info.recv = 0;
            info.send = 0;
            info.status = Login;
            infos[client.ip.s_addr] = info;
        }
        else
        {
            Information& info = infos[client.ip.s_addr];
            info.port = client.port;
//            info.recv = 0;
//            info.send = 0;
            info.status = Login;
        }
        sort(clients.begin(), clients.end(), sort_by_port);
        sendList(client_addr.sin_addr.s_addr, client.port);
        sendBufferedMessage(client_addr.sin_addr.s_addr, client.port);
        // send response
        Header resp;
        resp.type = RESPONSE;
        sendData(client_addr.sin_addr.s_addr, client.port, (char*) &resp,
                sizeof(resp));
        break;
    }

        // client received the list from server
    case LIST:
    {
//        cout << "recv list from " << inet_ntoa(client_addr.sin_addr) << endl;
        for (int i = 0; i < header.datasize; i++)
        {
            Client client;
            client.ip = client_addr.sin_addr;
            read(new_socket_fd, client.hostname, HOSTNAME_LEN);
            read(new_socket_fd, &client.ip, sizeof(client.ip));
            read(new_socket_fd, &client.port, sizeof(client.port));
            size_t j;
            for (j = 0; j < clients.size(); j++)
            {
                if (clients[j].ip.s_addr == client.ip.s_addr)
                {
                    clients[j] = client;
                    break;
                }
            }
            if (j == clients.size())
            {
                clients.push_back(client);
            }
        }
        break;
    }
    case MESSAGE:
    {
        Message message;
        read(new_socket_fd, &message, sizeof(message));
        if (serverMode)
        {
            message.from = client_addr.sin_addr.s_addr;
            Information& sender = infos[message.from];
            sender.send++;
            // buffer or relay
//            cout << message.to << endl;
            if (infos.find(message.to) == infos.end())
            {
                // not logged-in
                // buffer
                Information info;
                info.status = NotLogin;
                info.buffer.push_back(message);
                infos[message.to] = info;
            }
            else
            {

                Information& info = infos[message.to];
                if (isBlocked(message.from, info.blocks))
                {
                    return;
                }
                if (info.status == Exit)
                {

                    return;
                }
                else if (info.status == Logout)
                {

                    info.buffer.push_back(message);
                }
                else
                {
                    // relay
                    info.recv++;
                    sendMessageToClient(message.to, info.port, message);
                }
            }
            // statistics
        }
        else
        {
            // Event
            in_addr from;
            from.s_addr = message.from;
            cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
            cse4589_print_and_log("msg from:%s\n[msg]:%s\n", inet_ntoa(from),
                    message.message);
            cse4589_print_and_log("[%s:END]\n", "RECEIVED");
        }
        break;
    }

    case BROADCAST:
    {
        Message message;
        read(new_socket_fd, &message, sizeof(message));
        message.from = client_addr.sin_addr.s_addr;
        Information& sender = infos[message.from];
        sender.send++;
        // send message to every client or buffered
        for (size_t i = 0; i < clients.size(); i++)
        {
            // skip sender
            if (message.from == (int) clients[i].ip.s_addr)
            {
                continue;
            }
            Information& info = infos[clients[i].ip.s_addr];
            if (isBlocked(client_addr.sin_addr.s_addr, info.blocks))
            {
                continue;
            }
            if (info.status == Exit)
            {
                continue;
            }
            else if (info.status == Logout)
            {
                info.buffer.push_back(message);
            }
            else
            {
                // relay
                info.recv++;
                sendMessageToClient(clients[i].ip.s_addr, info.port, message);
            }
        }
        break;
    }

    case RESPONSE:
    {
        loggedin = true;
        cse4589_print_and_log("[%s:SUCCESS]\n", "LOGIN");
        cse4589_print_and_log("[%s:END]\n", "LOGIN");
        break;
    }

    case BLOCK:
    {
        Information& info = infos[client_addr.sin_addr.s_addr];
        for (size_t i = 0; i < info.blocks.size(); i++)
        {
            if (header.datasize == info.blocks[i])
            {
                return;
            }
        }
        info.blocks.push_back(header.datasize);
        break;
    }

    case UNBLOCK:
    {
        Information& info = infos[client_addr.sin_addr.s_addr];
        for (size_t i = 0; i < info.blocks.size(); i++)
        {
            if (header.datasize == info.blocks[i])
            {
                info.blocks.erase(info.blocks.begin() + i);
                break;
            }
        }
        break;
    }

    case REFRESH:
    {
        Information& info = infos[client_addr.sin_addr.s_addr];
        sendList(client_addr.sin_addr.s_addr, info.port);
        break;
    }
    case LOGOUT:
    {
        // set status to logged-out
        Information& info = infos[client_addr.sin_addr.s_addr];
        info.status = Logout;
        break;
    }

    case EXIT:
    {
        // set status to exit
        Information& info = infos[client_addr.sin_addr.s_addr];
        info.status = Exit;
        break;
    }

    case SENDFILE:
    {
        cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
        char filename[256];
        read(new_socket_fd, filename, 256);

        FILE* fp = fopen(filename, "wb");
        if (!fp)
        {
            cse4589_print_and_log("[%s:ERROR]\n", "RECEIVED");
            return;
        }
        char* data = new char[header.datasize];
        int total = header.datasize;
        int len = 0;
        while (len < total)
        {
            len += read(new_socket_fd, data + len, 1024);
        }
        fwrite(data, 1, header.datasize, fp);
        fclose(fp);
        delete[] data;
        cse4589_print_and_log("[%s:END]\n", "RECEIVED");
        break;
    }
    }
}

/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */
int main(int argc, char **argv)
{
    /*Init. Logger*/
    cse4589_init_log(argv[2]);

    /* Clear LOGFILE*/
    fclose(fopen(LOGFILE, "w"));

    /*Start Here*/
    bool exited = false;

    int port = atoi(argv[2]);

    if (argv[1][0] == 'c')
    {

    }
    else if (argv[1][0] == 's')
    {
        serverMode = true;
    }
    else
    {
        printf("Oops! Bad run mode!\n");
        return 1;
    }
    char hname[HOSTNAME_LEN];
    struct hostent *hent;

    gethostname(hname, sizeof(hname));
    hent = gethostbyname(hname);

    int socket_fd;
    socklen_t addr_length;
    struct sockaddr_in server_addr;
    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr, hent->h_addr, hent -> h_length);
    server_addr.sin_port = htons(port);
    if (bind(socket_fd, (struct sockaddr *) &server_addr, sizeof(server_addr))
            < 0)
    {
        cout << "bind error" << endl;
        exit(1);
    }
    else
    {
        addr_length = sizeof(server_addr);
        if (getsockname(socket_fd, (struct sockaddr *) &server_addr,
                &addr_length) < 0)
        {
            cout << "getsockname error" << endl;
            exit(1);
        }
        else
        {
            if (listen(socket_fd, 5) < 0)
            {
                cout << "listen error" << endl;
                exit(1);
            }
        }
    }

    fd_set rdfds;
    while (!exited)
    {
        FD_ZERO(&rdfds);
        FD_SET(STDIN_FILENO, &rdfds);
        FD_SET(socket_fd, &rdfds);
//        cout << "pre" << endl;
        select(socket_fd + 1, &rdfds, NULL, NULL, NULL);
//        cout << "select" << ret << endl;
        if (FD_ISSET(STDIN_FILENO, &rdfds))
        {
//            cout << "stdin" << endl;
            string line;
            getline(cin, line);
            stringstream ss(line);
            string command_str;
            ss >> command_str;
            if (command_str == "AUTHOR")
            {
                cse4589_print_and_log("[%s:SUCCESS]\n", command_str.c_str());
                cse4589_print_and_log(
                        "I, %s, have read and understood the course academic integrity policy.\n",
                        "qinxinti");
                cse4589_print_and_log("[%s:END]\n", command_str.c_str());
            }
            else if (command_str == "VERSION")
            {
                cout << "201703071722" << endl;
            }
            else if (command_str == "IP")
            {
                cse4589_print_and_log("[%s:SUCCESS]\n", command_str.c_str());
                cse4589_print_and_log("IP:%s\n",
                        inet_ntoa(*(struct in_addr*) (hent->h_addr)));
                cse4589_print_and_log("[%s:END]\n", command_str.c_str());
            }
            else if (command_str == "PORT")
            {
                cse4589_print_and_log("[%s:SUCCESS]\n", command_str.c_str());
                cse4589_print_and_log("PORT:%d\n", port);
                cse4589_print_and_log("[%s:END]\n", command_str.c_str());
            }
            else if (command_str == "LIST")
            {
                cse4589_print_and_log("[%s:SUCCESS]\n", command_str.c_str());
                for (size_t i = 0; i < clients.size(); i++)
                {
                    Client& client = clients[i];
                    cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", i + 1,
                            client.hostname, inet_ntoa(client.ip), client.port);
                }
                cse4589_print_and_log("[%s:END]\n", command_str.c_str());
            }
            else if (serverMode)
            {
                // server mode
                if (command_str == "STATISTICS")
                {
                    cse4589_print_and_log("[%s:SUCCESS]\n",
                            command_str.c_str());
                    for (size_t i = 0; i < clients.size(); i++)
                    {
                        Information& info = infos[clients[i].ip.s_addr];
//                        cout << clients[i].ip.s_addr << endl;
                        cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", i + 1,
                                clients[i].hostname, info.send, info.recv,
                                StatusNames[info.status]);
                    }
                    cse4589_print_and_log("[%s:END]\n", command_str.c_str());
                }
                else if (command_str == "BLOCKED")
                {
                    string ip;
                    ss >> ip;
                    if (!validate_ip(ip.c_str()))
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
                    int clientip = inet_addr(ip.c_str());
                    if (infos.find(clientip) == infos.end())
                    {
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        continue;
                    }
                    cse4589_print_and_log("[%s:SUCCESS]\n",
                            command_str.c_str());
                    Information& info = infos[clientip];
                    for (size_t i = 0; i < clients.size(); i++)
                    {
                        if (isBlocked(clients[i].ip.s_addr, info.blocks))
                        {
                            Client& client = clients[i];
                            cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", i + 1,
                                    client.hostname, inet_ntoa(client.ip),
                                    client.port);
                        }
                    }
                    cse4589_print_and_log("[%s:END]\n", command_str.c_str());
                }
            }
            else
            {
                // client mode
                if (command_str == "LOGIN")
                {

                    string server_ip;
                    string server_port;
                    ss >> server_ip >> server_port;

                    if (!validate_ip(server_ip.c_str())
                            || !validate_port(server_port.c_str()))
                    {
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }

                    Header header;
                    header.type = LOGIN;
                    header.datasize = sizeof(hname) + sizeof(port);
                    char* data = new char[sizeof(Header) + header.datasize];
                    memcpy(data, &header, sizeof(header));
                    memcpy(data + sizeof(header), hname, sizeof(hname));
                    memcpy(data + sizeof(header) + sizeof(hname), &port,
                            sizeof(port));

                    serverip = inet_addr(server_ip.c_str());
                    serverport = atoi(server_port.c_str());
                    sendData(serverip, serverport, data,
                            sizeof(Header) + header.datasize);
                    delete[] data;

                }
                else if (command_str == "REFRESH")
                {
                    if (!loggedin)
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
                    // send refresh

                    Header h;
                    h.type = REFRESH;
                    sendData(serverip, serverport, (char*) &h, sizeof(h));
                    cse4589_print_and_log("[%s:SUCCESS]\n",
                            command_str.c_str());
                    cse4589_print_and_log("[%s:END]\n", command_str.c_str());
                }
                else if (command_str == "SEND")
                {
                    if (!loggedin)
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
                    // send message
                    string ip;
                    ss >> ip;
                    if (!validate_ip(ip.c_str()))
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
//                    cout << ip << endl;
                    int clientip = inet_addr(ip.c_str());
                    size_t i;
                    for (i = 0; i < clients.size(); i++)
                    {
                        if (clientip == (int) clients[i].ip.s_addr)
                        {
                            break;
                        }
                    }
                    if (i == clients.size())
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }

                    if (clientip == (int) ((struct in_addr*) (hent->h_addr))->s_addr)
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                        command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                        command_str.c_str());
                        continue;
                    }
//                    cout << (unsigned) clientip << endl;
                    const char* msg = line.c_str() + ip.length() + 6;
                    Message message;
                    message.to = clientip;
                    strcpy(message.message, msg);
                    char* data = new char[sizeof(Header) + sizeof(Message)];
                    Header h;
                    h.type = MESSAGE;
                    h.datasize = sizeof(Message);
                    memcpy(data, &h, sizeof(h));
                    memcpy(data + sizeof(h), &message, sizeof(message));
                    sendData(serverip, serverport, data,
                            sizeof(Header) + sizeof(Message));
//                    cout << message.to << endl;
                    delete[] data;
                    cse4589_print_and_log("[%s:SUCCESS]\n",
                            command_str.c_str());
                    cse4589_print_and_log("[%s:END]\n", command_str.c_str());
                }
                else if (command_str == "BROADCAST")
                {
                    if (!loggedin)
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
                    // send message to -1
                    int clientip = -1;
                    const char* msg = line.c_str() + 10;
                    Message message;
                    message.to = clientip;
                    strcpy(message.message, msg);
                    char* data = new char[sizeof(Header) + sizeof(Message)];
                    Header h;
                    h.type = BROADCAST;
                    h.datasize = sizeof(Message);
                    memcpy(data, &h, sizeof(h));
                    memcpy(data + sizeof(h), &message, sizeof(message));
                    sendData(serverip, serverport, data,
                            sizeof(Header) + sizeof(Message));
                    delete[] data;
                    cse4589_print_and_log("[%s:SUCCESS]\n",
                            command_str.c_str());
                    cse4589_print_and_log("[%s:END]\n", command_str.c_str());
                }
                else if (command_str == "BLOCK")
                {
                    if (!loggedin)
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
                    // send block
                    string ip;
                    ss >> ip;
                    if (!validate_ip(ip.c_str()))
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
                    int clientip = inet_addr(ip.c_str());
                    size_t i;
                    for (i = 0; i < clients.size(); i++)
                    {
                        if (clientip == (int) clients[i].ip.s_addr)
                        {
                            break;
                        }
                    }
                    if (i == clients.size())
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }

                    if (clientip == (int) ((struct in_addr*) (hent->h_addr))->s_addr)
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                        command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                        command_str.c_str());
                        continue;
                    }
                    Header h;
                    h.type = BLOCK;
                    h.datasize = clientip;
                    sendData(serverip, serverport, (char*) &h, sizeof(h));
                    cse4589_print_and_log("[%s:SUCCESS]\n",
                            command_str.c_str());
                    cse4589_print_and_log("[%s:END]\n", command_str.c_str());
                }
                else if (command_str == "UNBLOCK")
                {
                    if (!loggedin)
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
                    // send unblock
                    string ip;
                    ss >> ip;
                    if (!validate_ip(ip.c_str()))
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
                    int clientip = inet_addr(ip.c_str());
                    size_t i;
                    for (i = 0; i < clients.size(); i++)
                    {
                        if (clientip == (int) clients[i].ip.s_addr)
                        {
                            break;
                        }
                    }
                    if (i == clients.size())
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }

                    if (clientip == (int) ((struct in_addr*) (hent->h_addr))->s_addr)
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                        command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                        command_str.c_str());
                        continue;
                    }
                    Header h;
                    h.type = UNBLOCK;
                    h.datasize = clientip;
                    sendData(serverip, serverport, (char*) &h, sizeof(h));
                    cse4589_print_and_log("[%s:SUCCESS]\n",
                            command_str.c_str());
                    cse4589_print_and_log("[%s:END]\n", command_str.c_str());
                }
                else if (command_str == "LOGOUT")
                {
                    if (!loggedin)
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
                    // send logout
                    Header h;
                    h.type = LOGOUT;
                    sendData(serverip, serverport, (char*) &h, sizeof(h));
                    loggedin = false;
                    cse4589_print_and_log("[%s:SUCCESS]\n",
                            command_str.c_str());
                    cse4589_print_and_log("[%s:END]\n", command_str.c_str());
                }
                else if (command_str == "EXIT")
                {
                    if (!loggedin)
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
                    // send exit
                    Header h;
                    h.type = EXIT;
                    sendData(serverip, serverport, (char*) &h, sizeof(h));
                    cse4589_print_and_log("[%s:SUCCESS]\n",
                            command_str.c_str());
                    cse4589_print_and_log("[%s:END]\n", command_str.c_str());
                    return 0;
                }
                else if (command_str == "SENDFILE")
                {
                    // send file to client
                    if (!loggedin)
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
                    // send exit
                    string ip;
                    ss >> ip;
                    int clientip = inet_addr(ip.c_str());
                    string filename;
                    ss >> filename;
                    size_t i;
                    for (i = 0; i < clients.size(); i++)
                    {
                        if (clientip == (int) clients[i].ip.s_addr)
                        {
                            break;
                        }
                    }
                    if (i == clients.size())
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
                    if (clientip == (int) ((struct in_addr*) (hent->h_addr))->s_addr)
                    {
                        //error
                        cse4589_print_and_log("[%s:ERROR]\n",
                        command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                        command_str.c_str());
                        continue;
                    }
                    Header h;
                    h.type = SENDFILE;
                    FILE* fp = fopen(filename.c_str(), "rb");
                    if (!fp)
                    {
                        cse4589_print_and_log("[%s:ERROR]\n",
                                command_str.c_str());
                        cse4589_print_and_log("[%s:END]\n",
                                command_str.c_str());
                        continue;
                    }
                    fseek(fp, 0, SEEK_END);
                    h.datasize = ftell(fp);
//                    cout << h.datasize << endl;
                    fseek(fp, 0, SEEK_SET);
                    char* data = new char[sizeof(Header) + 256 + h.datasize];
                    memcpy(data, &h, sizeof(h));
                    strcpy(data + sizeof(Header), filename.c_str());
                    fread(data + sizeof(Header) + 256, 1, h.datasize, fp);
                    fclose(fp);
//                    sendData(clients[i].ip.s_addr, clients[i].port, data,
//                            sizeof(Header) + 256 + h.datasize);
                    struct sockaddr_in serv_addr;
                    serv_addr.sin_family = AF_INET;
                    serv_addr.sin_port = htons(clients[i].port);
                    serv_addr.sin_addr.s_addr = clients[i].ip.s_addr;
                    bzero(&(serv_addr.sin_zero), 8);
                    int sockfd;
                    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                    {
                        cout << "create socket error" << endl;
                        exit(1);
                    }
                    if (connect(sockfd, (struct sockaddr *) &serv_addr,
                            sizeof(struct sockaddr)) < 0)
                    {
                        cout << "connect error" << endl;
                        continue;
                    }
                    int total = sizeof(Header) + 256 + h.datasize;
                    int len = 0;
                    while (len < total)
                    {
                        len += send(sockfd, data + len, 1024, 0);
                    }
                    close(sockfd);
                    delete[] data;
                    cse4589_print_and_log("[%s:SUCCESS]\n",
                            command_str.c_str());
                    cse4589_print_and_log("[%s:END]\n", command_str.c_str());
                    return 0;
                }
            }
        }
        if (FD_ISSET(socket_fd, &rdfds))
        {
//            cout << "scoket" << endl;
            recvData(socket_fd);
        }
    }

    return 0;
}
