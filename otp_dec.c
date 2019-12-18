#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

// otp_dec sends ciphertext and a corresponding key to otp_dec_d to be deciphered.  otp_dec then waits for otp_dec_d to send the resulting
// plaintext back to it.  when otp_dec receives the plaintext, it outputs it to stdout.
// Additionally, this code is essentially identical to the code in found in otp_enc, so the comments are really really light (I don't want to have to repeat
// myself!).  However, I do comment extensively on the blocks of code that have changed.
char *yes = "Yes!";
#define BUFFERLENGTH 100000
const char alphas[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ "};
void error(const char *msg);
// The name of this function is changed (from sendToEncD).  Otherwise, the it functions identically
void sendToDecD(char *buffer, int socketFD);

int main(int argc, char *argv[])
{
    int socketFD, portNumber, charsRead, i, counter;
    FILE *fileD;
    struct sockaddr_in serverAddress;
    struct hostent *serverHostInfo;
    // The big change in otp_dec is that PTbuffer is changed to CBuffer!
    char keyBuffer[BUFFERLENGTH], CBuffer[BUFFERLENGTH], buffer[BUFFERLENGTH];

    if (argc != 4)
    {
        fprintf(stderr, "USAGE: %s hostname port\n", argv[0]);
        exit(0);
    } // Check usage & args

    // Set up the server address struct
    memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
    portNumber = atoi(argv[3]);                                  // Get the port number, convert to an integer from a string
    serverAddress.sin_family = AF_INET;                          // Create a network-capable socket
    serverAddress.sin_port = htons(portNumber);                  // Store the port number
    serverHostInfo = gethostbyname("localhost");                 // Convert the machine name into a special form of address
    if (serverHostInfo == NULL)
    {
        fprintf(stderr, "CLIENT: ERROR, no such host\n");
        exit(0);
    }
    memcpy((char *)&serverAddress.sin_addr.s_addr, (char *)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

    // Set up the socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
    if (socketFD < 0)
    {
        error("CLIENT: ERROR opening socket");
    }

    // Connect to server
    if (connect(socketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
    {
        error("CLIENT: ERROR connecting");
    }

    // Send message to server
    // otp_dec sends otp_dec as a verification m essage to otp_dec_d (as opposed to otp_enc);
    memset(buffer, '\0', sizeof(buffer));
    strcpy(buffer, "otp_dec");
    sendToDecD(buffer, socketFD);

    memset(buffer, '\0', sizeof(buffer));                      // Clear out the buffer again for reuse
    charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
    if (charsRead < 0)
    {
        error("CLIENT: ERROR reading from socket");
    }
    if (strcmp(buffer, yes) != 0)
    {
        fprintf(stderr, "Error: could not contact otp_dec_d on port %d\n", argv[3]);
        exit(2);
    }

    // Sending cipherText to otp_dec_d to be decrypted
    // Everything here is pretty much the same.  We're still making sure the ciphertext doesn't have any illegal characters (although that proably isn't necessary)
    memset(CBuffer, '\0', sizeof(CBuffer));
    fileD = fopen(argv[1], "r");
    while (fgets(CBuffer, BUFFERLENGTH, fileD) != NULL)
        ;
    fclose(fileD);
    counter = 0;
    i = 0;
    while (i < strlen(alphas) && counter < strlen(CBuffer))
    {
        if (CBuffer[counter] == alphas[i])
        {
            i = -1;
            counter++;
        }
        if (CBuffer[counter] == '\n')
        {
            CBuffer[counter] = '!';
            break;
        }
        i++;
    }
    if (CBuffer[counter] != '!')
    {
        perror("Error: Illegal character in CipherText!\n");
        exit(1);
    }
    sendToDecD(CBuffer, socketFD);
    // Sending the ciphertext's associated key to otp_dec_d
    memset(keyBuffer, '\0', sizeof(keyBuffer));
    fileD = fopen(argv[2], "r");
    while (fgets(keyBuffer, BUFFERLENGTH, fileD) != NULL)
        ;
    fclose(fileD);
    if (strlen(keyBuffer) < strlen(CBuffer))
    {
        perror("Error: Key's length is not sufficient.\n");
        exit(1);
    }
    for (i = 0; i < strlen(keyBuffer); i++)
    {
    }
    counter = 0;
    i = 0;
    while (i < strlen(alphas) && counter < strlen(keyBuffer))
    {
        if (keyBuffer[counter] == alphas[i])
        {
            i = -1;
            counter++;
        }
        if (keyBuffer[counter] == '\n')
        {
            keyBuffer[counter] = '*';
            break;
        }
        i++;
    }
    if (keyBuffer[counter] != '*')
    {
        perror("Error: Illegal character in key!\n");
        exit(1);
    }
    sendToDecD(keyBuffer, socketFD);

    int check = 0, bufferIter = 0;
    memset(buffer, '\0', BUFFERLENGTH);
    i = 0;
    charsRead = 0;
    do
    {
        charsRead = recv(socketFD, &buffer[i], BUFFERLENGTH, 0);
        i += charsRead;
        bufferIter = strlen(buffer);
    } while (buffer[bufferIter - 1] != '!');
    buffer[bufferIter - 1] = '\n';
    write(STDOUT_FILENO, buffer, strlen(buffer));
    close(socketFD); // Close the socket
    return 0;
}

void error(const char *msg)
{
    perror(msg);
    exit(1);
}

void sendToDecD(char *buffer, int socketFD)
{
    int i = 0, charsRead = 0, sent = strlen(buffer), checkSend = -5;
    do
    {
        charsRead = send(socketFD, &buffer[i], sent - i, 0);
        i += charsRead;
    } while (i < sent);

    do
    {
        ioctl(socketFD, TIOCOUTQ, &checkSend); // Check the send buffer for this socket
    } while (checkSend > 0);                   // Loop forever until send buffer for this socket is empty
    if (checkSend < 0)
    {
        error("ioctl error");
    }
}