#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

// otp_dec_d is designed to emulate a daemon.  It runs in the background and waits to receive ciphertext and a key from otp_dec.  If that is successful, it will decrypt
// the ciphertext and then send the resulting plaintext back to otp_dec.  It has the ability to spawn and manage 5 simultaneous child processes. Each one can encrypt received ciphertext
// and then send the resulting plaintext to otp_dec.
// otp_dec_d is virtually identical to otp_enc_d (so please look at the comments in that to understand code in this).  However, I comment extensively on the parts that have been changed.
//  I defined a massive and arbitrary length for my various buffers
#define BUFFERLENGTH 150000
// ConnectCheck is checking for otp_dec instead of otp_enc in otp_dec_d
const char *connectCheck = "otp_dec";
const char alphas[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ "};

void error(const char *msg);
int connectionCheck(int establishedConnectionFD, char *buffer);

int main(int argc, char *argv[])
{
    int listenSocketFD, establishedConnectionFD, portNumber, charsRead, childTotal = 0, bgStatus = 0, i, j;
    socklen_t sizeOfClientInfo;
    // PTBuffer has been changed to CBuffer for in otp_dec_d
    char buffer[BUFFERLENGTH], keyBuffer[BUFFERLENGTH], CBuffer[BUFFERLENGTH];
    struct sockaddr_in serverAddress, clientAddress;
    pid_t childPid;

    if (argc != 2)
    {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    } // Check usage & args

    // Set up the address struct for this process (the server)
    memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
    portNumber = atoi(argv[1]);                                  // Get the port number, convert to an integer from a string
    serverAddress.sin_family = AF_INET;                          // Create a network-capable socket
    serverAddress.sin_port = htons(portNumber);                  // Store the port number
    serverAddress.sin_addr.s_addr = INADDR_ANY;                  // Any address is allowed for connection to this process

    // Set up the socket
    listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
    if (listenSocketFD < 0)
    {
        error("ERROR opening socket");
    }

    // Enable the socket to begin listening
    if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
    {
        error("ERROR on binding");
    }

    listen(listenSocketFD, 5);

    for(;;)
    {
        if (childTotal <= 5)
        {

            sizeOfClientInfo = sizeof(clientAddress);
            establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
            if (establishedConnectionFD < 0)
            {
                error("ERROR on accept");
            }

            if ((childPid = fork()) == -1)
            {
                perror("The fork failed!");
                break;
            }
            else if (childPid == 0)
            {

                memset(buffer, '\0', BUFFERLENGTH);
                charsRead = recv(establishedConnectionFD, buffer, BUFFERLENGTH, 0); // Read the client's message from the socket
                if (charsRead < 0)
                {
                    error("ERROR reading from socket");
                }
                if (connectionCheck(establishedConnectionFD, buffer) != 0)
                {
                    exit(0);
                }
                else
                {

                    int bufferIter = 0;
                    memset(buffer, '\0', BUFFERLENGTH);
                    i = 0;
                    do
                    {
                        charsRead = recv(establishedConnectionFD, &buffer[i], BUFFERLENGTH, 0);
                        i += charsRead;
                        bufferIter = strlen(buffer);
                    } while (buffer[bufferIter - 1] != '*');

                    char tempBuffer[BUFFERLENGTH];
                    memset(tempBuffer, '\0', BUFFERLENGTH);
                    memset(keyBuffer, '\0', BUFFERLENGTH);
                    memset(CBuffer, '\0', BUFFERLENGTH);
                    for (i = 0, j = 0;; i++, j++)
                    {
                        tempBuffer[j] = buffer[i];
                        if (tempBuffer[j] == '!')
                        {
                            strcpy(CBuffer, tempBuffer);

                            break;
                        }
                    }
                    memset(tempBuffer, '\0', BUFFERLENGTH);
                    for (i = strlen(CBuffer), j = 0;; i++, j++)
                    {
                        tempBuffer[j] = buffer[i];
                        if (tempBuffer[j] == '*')
                        {
                            strcpy(keyBuffer, tempBuffer);
                            j = 0;
                            break;
                        }
                    }
                    if (strlen(keyBuffer) >= strlen(CBuffer))
                    {

                        memset(buffer, '\0', BUFFERLENGTH);
                        int counter = 0, num;
                        //This is the block of code where otp_dec_d truly diverges from otp_enc_d.  Also, these series of loops broke my program for a while, because I
                        // foolishly tested out my math on a scientific calculator instead of checking to see how C handled it.
                        // For example (4-23) mod 27 = 8 on the windows scientific calculator
                        // In C, (4-23) mod 27 = -19
                        // This might have been explained in the lecture notes or the instructions for this assignment, but I didn't catch it if it was.
                        // This thread at stackoverflow has a good explanation as to why this is the case:
                        // https: //stackoverflow.com/questions/450410/why-is-modulus-different-in-different-programming-languages
                        // "Almost every programming language will require that (a/n) * n + (a%n) = a. So the definition of modulus will nearly always depend on 
                        // the definition of integer division. There are two choices for integer division by negative numbers 2/-18 = 0 or 2/-18 = -1. Depending on 
                        // which one is true for your language will usually change the % operator."
                        // Anyway, my original code was simply: (CipherIndex - KeyIndex) mod 27
                        // I changed it to: (CipherIndex - KeyIndex) + (if result less than 0 add 27) or (if result greater than or equal to 0, add 0)
                        while (1)
                        {
                            if (CBuffer[counter] != '!')
                            {
                                for (i = 0;; i++)
                                {
                                    // Finding where the CBuffer character's match in the alphas array and putting the index into num
                                    if (CBuffer[counter] == alphas[i])
                                    {
                                        num = i;

                                        break;
                                    }
                                }
                                for (i = 0; counter < strlen(keyBuffer); i++)
                                {
                                    // Finding the keyBuffer character's match in the alphas array and subtracting the index from num
                                    if (keyBuffer[counter] == alphas[i])
                                    {

                                        num -= i;

                                        break;
                                    }
                                }
                            }
                            // If num is less than 0, we add 27.  If it is greater than or equal to 0, we add nothing.
                            if (CBuffer[counter] != '!')
                            {
                                if (num < 0)
                                {
                                    num += 27;
                                }
                                buffer[counter] = alphas[num];
                                num = 0;
                                counter++;
                            }

                            else
                            {
                                buffer[counter] = '!';
                                int charsWritten = 0, sent;
                                i = 0;
                                charsRead = 0;
                                sent = strlen(buffer);
                                do
                                {
                                    charsRead = send(establishedConnectionFD, &buffer[i], sent - i, 0);
                                    i += charsRead;
                                } while (i < sent);

                                int checkSend = -5; // Holds amount of bytes remaining in send buffer
                                do
                                {
                                    ioctl(establishedConnectionFD, TIOCOUTQ, &checkSend); // Check the send buffer for this socket
                                } while (checkSend > 0);                                  // Loop forever until send buffer for this socket is empty
                                if (checkSend < 0)
                                {
                                    error("ioctl error");
                                }
                                break;
                            }
                        }
                    }
                    else
                    {
                        exit(0);
                    }
                    close(establishedConnectionFD);
                }
            }
            else
            {
                childTotal++;
            }
        }

        else
        {
            if ((childPid = waitpid(-1, &bgStatus, 0)) > 0)
            {
                childTotal--;
            }
        }
    }
    return 0;
}

void error(const char *msg)
{
    perror(msg);
    exit(1);
}
int connectionCheck(int establishedConnectionFD, char *buffer)
{
    if (strcmp(buffer, connectCheck) == 0)
    {
        if ((send(establishedConnectionFD, "Yes!", 4, 0)) < 0)
        {
            error("ERROR writing to socket");
        }
        return 0;
    }
    if ((send(establishedConnectionFD, "No!", 3, 0)) < 0)
    {
        error("ERROR writing to socket");
    }
    return 1;
}
