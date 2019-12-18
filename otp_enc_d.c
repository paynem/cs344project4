#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

// otp_enc_d is designed to emulate a daemon.  It runs in the background and waits to receive plaintext and a key from otp_enc.  If that is successful, it will encrypt
// the plaintext and then send the resulting ciphertext back to otp_enc.  It has the ability to spawn and manage 5 simultaneous child processes. Each one can encrypt received plaintext
// and then send the resulting ciphertext to otp_enc.
//  I defined a massive and arbitrary length for my various buffers
#define BUFFERLENGTH 150000

// connectCheck is used to verify that otp_enc is trying to connect to it (anything else is rejected).
const char *connectCheck = "otp_enc";
// This array is used to encrypt plaintext.
const char alphas[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ "};

// error is a function that is used to generate error messages and close the program
void error(const char *msg);
// connectionCheck makes sure that only otp_enc can connect to otp_enc_d
int connectionCheck(int establishedConnectionFD, char *buffer);

int main(int argc, char *argv[])
{
    // Much of the early code in otp_enc_d is taken from professor Brewster's server.c program.
    // listenSocketFD is used to server socket that listens on the passed in port number.
    // establishedConnectionFD is used as a file descriptor for the chosen connecton to exclusively use when a connection is actually made
    // portNumber is the passed in port number
    // charsRead is used later in during send and receive attempts to make sure that data is actually being, well, sent and received
    // childTotal is used to keep track of how many child processes we have running (per the assignment, we cannot exceed 5)
    // bgStatus is used when processing background processes that have ended
    // i and j are generic all-purpose counters
    int listenSocketFD, establishedConnectionFD, portNumber, charsRead, childTotal = 0, bgStatus = 0, i, j;
    // sizeOfClientInfo is used to hold the size of the address struct
    socklen_t sizeOfClientInfo;
    // keyBuffer holds the received key
    // PTBuffer holds the received plaintext
    // buffer is used to hold a variety of strings
    char buffer[BUFFERLENGTH], keyBuffer[BUFFERLENGTH], PTBuffer[BUFFERLENGTH];
    // setting up the address structs for the server and client
    struct sockaddr_in serverAddress, clientAddress;
    // Setting up child processes
    pid_t childPid;

    // Making sure we'e received the correct number of arguments (program name, port#).  If not, an error is printed, and the program exits
    if (argc != 2)
    {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    } 

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

    // Flip the socket on - it can now receive up to 5 connections
    listen(listenSocketFD, 5);

    // Starting our main program loop so that the program runs indefinitely and waits for incoming connection attempts
    for(;;)
    {
        // If the total number of children is greater than 5, we cannot create any more proccesses
        if (childTotal <= 5)
        {
            // Waiting for incoming connection (if there is one, a connection is started with a new file descriptor (establishedConnectionFD))
            sizeOfClientInfo = sizeof(clientAddress);
            establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
            if (establishedConnectionFD < 0)
            {
                error("ERROR on accept");
            }
            // We try to start a new child process with fork once a connection attempt has been accepted
            if ((childPid = fork()) == -1)
            {
                perror("The fork failed!");
                break;
            }
            // If the child process starts up successfully, we give it something to do
            else if (childPid == 0)
            {
                // Clearing out buffer, so we can use it
                memset(buffer, '\0', BUFFERLENGTH);
                // Waiting to receive verification message from otp_enc.  This is an incredibly short message, so I didn't put too many protections or checks in place
                // Although I really should have.
                charsRead = recv(establishedConnectionFD, buffer, BUFFERLENGTH, 0); // Read the client's message from the socket
                if (charsRead < 0)
                {
                    error("ERROR reading from socket");
                }
                // We call connectionChecck to make sure that the incoming connection is coming from otp_enc.  If it isn't, we end the process
                if (connectionCheck(establishedConnectionFD, buffer) != 0)
                {

                    exit(0);
                }
                // We've received a valid connection, so the process starts attemping to receive the plaintext and key
                else
                {
                    // So, i is set to equal the number of characters that have been read (it obviously starts out at 0).  Everytime, we receive a chunk/batch/whatever of characters, we
                    // increase i by charsRead (which is the number of characters received in a single transaction).  bufferIter is then set to equal the current length of buffer.  When
                    // buffer[bufferIter -1] == '*', we've received the both the key and plaintext otp_enc, and we can end the loop.  But yeah, the general structure for this was mostly got from instructor
                    // Cuneo (I had something sort of similar, but it was wrong and it wasn't working consistantly);
                    int bufferIter = 0;
                    memset(buffer, '\0', BUFFERLENGTH);
                    i = 0;
                    do
                    {
                        charsRead = recv(establishedConnectionFD, &buffer[i], BUFFERLENGTH, 0);
                        i += charsRead;
                        bufferIter = strlen(buffer);
                    } while (buffer[bufferIter - 1] != '*');
                    // Setting up a temp buffer, put the key and plaintext into separate character arrays
                    char tempBuffer[BUFFERLENGTH];
                    // Clearing out tempBuffer, keyBuffer, and PTBuffer
                    memset(tempBuffer, '\0', BUFFERLENGTH);
                    memset(keyBuffer, '\0', BUFFERLENGTH);
                    memset(PTBuffer, '\0', BUFFERLENGTH);
                    // I actually screwed this up at first, and it took me ages to figure out why.  My original code attached an additional character to my key, which ruined
                    // all of my encryptions.
                    // This NEW AND IMPROVED code uses the ! character to isolate the plaintext from buffer.  It moves it to tempbuffer and then to PTBuffer.
                    for (i = 0, j = 0;; i++, j++)
                    {
                        tempBuffer[j] = buffer[i];
                        if (tempBuffer[j] == '!')
                        {
                            strcpy(PTBuffer, tempBuffer);
                            break;
                        }
                    }
                    // We then clear tempbuffer and start the process over.  Except this time, we're trying to isolate and grab the key from buffer (this is why i is set to be
                    // equal to the length of PTBuffer)
                    memset(tempBuffer, '\0', BUFFERLENGTH);
                    for (i = strlen(PTBuffer), j = 0;; i++, j++)
                    {
                        tempBuffer[j] = buffer[i];
                        if (tempBuffer[j] == '*')
                        {
                            strcpy(keyBuffer, tempBuffer);
                            j = 0;
                            break;
                        }
                    }
                    //  Just double-checkin to make sure the key is the correct length (although otp_enc should take care of this)
                    if (strlen(keyBuffer) >= strlen(PTBuffer))
                    {
                        // Since it is, we start process of encrypting the received plaintext.
                        memset(buffer, '\0', BUFFERLENGTH);
                        int counter = 0, num;
                        // Until we reach the ! character, we iterate through both the plaintext and the key.  For each character (in the plaintext and key), we look for a match
                        // in the alpha array.  When a match is found, we take resulting index.  The the indices generated from the plaintext and the key are added, and the resulting 
                        // sum has mod 27 applied to it.  That resulting number is then used to pull a character from the alphas array.  This process is repeated until we reach the end of 
                        // the plaintext buffer.  The resulting characters (which are inserted in order into another buffer) are the ciphertext that is going to be sent to otp_enc.
                        while (1)
                        {
                            // We keep going until the end of the plaintext buffer (the ! signifies this)
                            if (PTBuffer[counter] != '!')
                            {
                                // Looking for the plaintext character's match in alphas.  Once we find the number, we store it in num and end the loop.
                                for (i = 0;; i++)
                                {
                                    if (PTBuffer[counter] == alphas[i])
                                    {

                                        num = i;
                                        break;
                                    }
                                }
                                // Find the key character's match in alphas.  Once we find the number, we add it to num and end the loop.
                                for (i = 0; counter < strlen(keyBuffer); i++)
                                {

                                    if (keyBuffer[counter] == alphas[i])
                                    {
                                        num += i;
                                        break;
                                    }
                                }
                            }
                            //  If we haven't hit the end of the plaintext buffer, we take num and apply mod 27 to it.  The result is then used to grab a character from alphas, which
                            // is then stuck into buffer (to build up our ciphertext).
                            if (PTBuffer[counter] != '!')
                            {
                                buffer[counter] = alphas[num % 27];
                                num = 0;
                                counter++;
                            }
                            // Now that we've generated our ciphertext, we need to send it to otp_enc
                            else
                            {
                                // The send code is identical to the code used in otp_enc (and very similar to the receive code used earlier in this program).  Check
                                // those comments for an explanation as to how this works.
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
                                // We've sent the ciphertext, so we're exiting the loop.
                                break;
                            }
                        }
                    }
                    // If our key is too short, we exit the process
                    else
                    {
                        exit(0);
                    }
                    // The process has finished its task, so it closes the connection.
                    close(establishedConnectionFD);
                }
            }
            // Parent process keeps track of how many children it has via childTotal (we just added a process, so we increment by 1)
            else
            {
                childTotal++;
            }
        }
        // Checking to see if any child processes have ended.  if so, we decrement childTotal by 1.
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

// Professor Brewster's error funtion
void error(const char *msg)
{
    perror(msg);
    exit(1);
}
// connectionCheck makes sure that the connection request is coming from otp_enc.  if it isn't, it sends a rejection message to the client and then rejects the connection.
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
