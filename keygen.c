#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
//This program is a key generator.  It takes an integer as an argument and generates a string of equal length that can only
// consist of the characters found in keyGenArr (right below this comment).
const char keyGenArr[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ "};

int main(int argc, char *argv[])
{
    // Getting my random number generation set up (using time as a seed)
    srand(time(0));
    // If the user doesn't input the correct amount of arguments, the program outputs a message to stderr and exits.
    if (argc != 2)
    {
        fprintf(stderr, "Incorrect number of arguments passed to keygen.\n");
        exit(1);
    }

    // using the passed in key length to malloc the correct length.
    char *key;
    int num, i, j, keyLength = atoi(argv[1]);
    key = malloc(keyLength * sizeof(char) + 2);

    // Randomly generating a number from 0 to 26 (the keyGenArr has 27 elements, which includes all capital letters and space)
    for (i = 0; i < keyLength; i++)
    {
        key[i] = (keyGenArr[rand() % 27]);
    }
    // Inserting a newline and then a terminating zero at the end of the key
    key[i] = '\n';
    i++;
    key[i] = '\0';

    // Outputting the key to stdout
    write(STDOUT_FILENO, key, keyLength + 1);
    fflush(stdout);
    // Freeing up the space on the heap!
    free(key);

    return (0);
}