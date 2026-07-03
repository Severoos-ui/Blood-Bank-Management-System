#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

/* -- Color Codes ------------------------------- */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define BOLD    "\033[1m"
#define RESET   "\033[0m"

/* -- File Names -------------------------------- */
#define FILENAME     "donors.txt"
#define CREDENTIALS  "credentials.txt"

/* -- Donor Structure --------------------------- */
struct Donor
{
    int  id;
    char name[50];
    int  age;
    char bloodGroup[5];
    char phone[15];
    char address[100];
};



#define DIGEST_LEN 32

static void hashPassword(const char *password, char outHex[DIGEST_LEN * 2 + 1])
{
    uint8_t digest[DIGEST_LEN];
    memset(digest, 0, sizeof(digest));

    size_t len = strlen(password);
    uint8_t carry = 0xA5;   /* non-zero seed */

    for (size_t i = 0; i < len; i++)
    {
        uint8_t c = (uint8_t)password[i];
        /* mix byte with position, carry, and a prime */
        uint8_t mixed = c ^ (uint8_t)(i * 31 + carry);
        /* left-rotate by 3 */
        mixed = (mixed << 3) | (mixed >> 5);
        /* update carry for next round (avalanche) */
        carry = mixed ^ (uint8_t)(carry * 17);
        /* fold into digest */
        digest[i % DIGEST_LEN] ^= mixed;
        /* secondary diffusion pass */
        for (int j = 0; j < DIGEST_LEN; j++)
            digest[j] ^= (uint8_t)((digest[(j + 1) % DIGEST_LEN] * 3) ^ carry);
    }

    /* final diffusion: forward + backward pass */
    for (int pass = 0; pass < 3; pass++)
    {
        for (int j = 0; j < DIGEST_LEN; j++)
            digest[j] ^= (uint8_t)(digest[(j + 1) % DIGEST_LEN] ^ (j * 7 + 0x5C));
        for (int j = DIGEST_LEN - 1; j >= 0; j--)
            digest[j] ^= (uint8_t)(digest[(j + DIGEST_LEN - 1) % DIGEST_LEN] ^ (j * 13 + 0x36));
    }

    /* convert to hex string */
    for (int i = 0; i < DIGEST_LEN; i++)
        sprintf(outHex + i * 2, "%02x", digest[i]);
    outHex[DIGEST_LEN * 2] = '\0';
}

/* ================================================
   CREDENTIALS FILE
   Format: username|hashed_password
================================================ */

static void saveCredentials(const char *username, const char *hashedPwd)
{
    FILE *fp = fopen(CREDENTIALS, "w");
    if (!fp) return;
    fprintf(fp, "%s|%s\n", username, hashedPwd);
    fclose(fp);
}

/* Returns 1 if credentials file exists, 0 otherwise */
static int credentialsExist()
{
    FILE *fp = fopen(CREDENTIALS, "r");
    if (!fp) return 0;
    fclose(fp);
    return 1;
}

/* Returns 1 on valid login, 0 on failure */
static int verifyLogin(const char *username, const char *password)
{
    FILE *fp = fopen(CREDENTIALS, "r");
    if (!fp) return 0;

    char storedUser[50];
    char storedHash[DIGEST_LEN * 2 + 1];
    char line[200];

    while (fgets(line, sizeof(line), fp))
    {
        line[strcspn(line, "\n")] = '\0';
        char *tok = strtok(line, "|");
        if (!tok) continue;
        strncpy(storedUser, tok, 49);
        storedUser[49] = '\0';

        tok = strtok(NULL, "|");
        if (!tok) continue;
        strncpy(storedHash, tok, DIGEST_LEN * 2);
        storedHash[DIGEST_LEN * 2] = '\0';

        if (strcmp(storedUser, username) == 0)
        {
            char inputHash[DIGEST_LEN * 2 + 1];
            hashPassword(password, inputHash);
            fclose(fp);
            return strcmp(inputHash, storedHash) == 0;
        }
    }

    fclose(fp);
    return 0;
}

/* ================================================
   SETUP WIZARD — runs only once (first launch)
================================================ */

static void firstTimeSetup()
{
    printf(CYAN "\n+--------------------------------------+\n");
    printf(     "¦ SETUP ->  CREATE ADMIN  ¦\n");
    printf(     "+--------------------------------------+\n" RESET);
    printf(YELLOW " Please create an admin account.\n\n" RESET);

    char username[50];
    char password[100];
    char confirm[100];

    /* Username */
    while (1)
    {
        printf("  Create Username : ");
        scanf(" %49[^\n]", username);
        if (strlen(username) >= 3) break;
        printf(RED "  Username must be at least 3 characters.\n" RESET);
    }

    /* Password */
    while (1)
    {
        printf("  Create Password : ");
        scanf(" %99[^\n]", password);

        if (strlen(password) < 6)
        {
            printf(RED "  Password must be at least 6 characters.\n" RESET);
            continue;
        }

        printf("  Confirm Password: ");
        scanf(" %99[^\n]", confirm);

        if (strcmp(password, confirm) == 0) break;
        printf(RED "  Passwords do not match. Try again.\n" RESET);
    }

    char hashed[DIGEST_LEN * 2 + 1];
    hashPassword(password, hashed);
    saveCredentials(username, hashed);

    printf(GREEN "\n  [+] Admin account created successfully!\n" RESET);
    printf(CYAN  "  [*] Password is encrypted and stored in '%s'\n" RESET, CREDENTIALS);
}

/* ================================================
   LOGIN SCREEN
================================================ */

static void loginScreen()
{
    printf(CYAN "\n+-------------------------------------------+\n");
    printf(     "  BLOOD BANK MANAGEMENT SYSTEM -SECURE LOGIN \n");
    printf(       "+-------------------------------------------+\n" RESET);

    char username[50];
    char password[100];
    int  attempts = 0;
    const int MAX_ATTEMPTS = 3;

    while (attempts < MAX_ATTEMPTS)
    {
        printf("\n  Username : ");
        scanf(" %49[^\n]", username);
        printf("  Password : ");
        scanf(" %99[^\n]", password);

        if (verifyLogin(username, password))
        {
            printf(GREEN "\n  [?] Access Granted ! \n Welcome to system- %s.\n" RESET, username);
            return;   /* access granted */
        }

        attempts++;
        int remaining = MAX_ATTEMPTS - attempts;
        if (remaining > 0)
            printf(RED "\n  [!] Invalid username or password . %d attempt remaining.\n" RESET, remaining);
    }

    /* Too many failed attempts */
    printf(RED "\n ...... Too many failed attempts. \n Access denied.\n\n" RESET);
    exit(1);
}

/* ================================================
   CHANGE PASSWORD (menu option)
================================================ */

static void changePassword()
{
    printf(CYAN "\n===== CHANGE PASSWORD =====\n" RESET);

    char username[50];
    char oldPwd[100];
    char newPwd[100];
    char confirm[100];

    printf("  Current Username : ");
    scanf(" %49[^\n]", username);
    printf("  Current Password : ");
    scanf(" %99[^\n]", oldPwd);

    if (!verifyLogin(username, oldPwd))
    {
        printf(RED "  [!] Current credentials are incorrect.\n" RESET);
        return;
    }

    while (1)
    {
        printf("  New Password     : ");
        scanf(" %99[^\n]", newPwd);

        if (strlen(newPwd) < 6)
        {
            printf(RED "  Password must be at least 6 characters.\n" RESET);
            continue;
        }

        printf("  Confirm Password : ");
        scanf(" %99[^\n]", confirm);

        if (strcmp(newPwd, confirm) == 0) break;
        printf(RED "  Passwords do not match. Try again.\n" RESET);
    }

    char hashed[DIGEST_LEN * 2 + 1];
    hashPassword(newPwd, hashed);
    saveCredentials(username, hashed);

    printf(GREEN "\n  [+] Password changed successfully!\n" RESET);
}

/* ================================================
   HELPER / TABLE FUNCTIONS
================================================ */

void clearBuffer()
{
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF);
}

void printTableHeader()
{
    printf(CYAN);
    printf("  +--------+----------------------------+---------+-------------+--------------+------------------------------+\n");
    printf("  | %-6s | %-26s | %-7s | %-11s | %-12s | %-28s |\n",
           "ID", "Name", "Age", "Blood Group", "Phone", "Address");
    printf("  +--------+----------------------------+---------+-------------+--------------+------------------------------+\n");
    printf(RESET);
}

void printTableRow(struct Donor *d)
{
    printf("  | " YELLOW "%-6d" RESET
           " | " BOLD   "%-26s" RESET
           " | %-7d"
           " | " RED    "%-11s" RESET
           " | %-12s"
           " | %-28s |\n",
           d->id, d->name, d->age, d->bloodGroup, d->phone, d->address);
}

void printTableFooter()
{
    printf(CYAN
           "  +--------+----------------------------+---------+-------------+--------------+------------------------------+\n"
           RESET);
}

/* ================================================
   PHONE VALIDATION HELPER
   Rules: exactly 10 digits, must start with 97 or 98
================================================ */

static int isValidPhone(const char *phone)
{
    if (strlen(phone) != 10) return 0;
    for (int i = 0; phone[i]; i++)
        if (!isdigit((unsigned char)phone[i])) return 0;
    if (!(phone[0] == '9' && (phone[1] == '7' || phone[1] == '8'))) return 0;
    return 1;
}

/* ================================================
   FILE FUNCTIONS
================================================ */

void saveToFile(struct Donor d[], int count)
{
    FILE *fp = fopen(FILENAME, "w");

    if (fp == NULL)
    {
        printf(RED "  [!] Error: Could not open %s for writing!\n" RESET, FILENAME);
        return;
    }

    for (int i = 0; i < count; i++)
    {
        fprintf(fp, "%d|%s|%d|%s|%s|%s\n",
                d[i].id, d[i].name, d[i].age,
                d[i].bloodGroup, d[i].phone, d[i].address);
    }

    fclose(fp);
    printf(GREEN "  [+] Records saved to %s\n" RESET, FILENAME);
}

int loadFromFile(struct Donor d[])
{
    FILE *fp = fopen(FILENAME, "r");
    if (fp == NULL) return 0;

    int  count = 0;
    char line[200];

    while (fgets(line, sizeof(line), fp) != NULL && count < 100)
    {
        line[strcspn(line, "\n")] = '\0';
        char *token;

        token = strtok(line, "|");
        if (!token) continue;
        d[count].id = atoi(token);

        token = strtok(NULL, "|");
        if (!token) continue;
        strncpy(d[count].name, token, 49);
        d[count].name[49] = '\0';

        token = strtok(NULL, "|");
        if (!token) continue;
        d[count].age = atoi(token);

        token = strtok(NULL, "|");
        if (!token) continue;
        strncpy(d[count].bloodGroup, token, 4);
        d[count].bloodGroup[4] = '\0';

        token = strtok(NULL, "|");
        if (!token) continue;
        strncpy(d[count].phone, token, 14);
        d[count].phone[14] = '\0';

        token = strtok(NULL, "|");
        if (!token)
            d[count].address[0] = '\0';
        else
        {
            strncpy(d[count].address, token, 99);
            d[count].address[99] = '\0';
        }

        count++;
    }

    fclose(fp);
    return count;
}

/* ================================================
   MAIN
================================================ */

int main()
{
    /* ---- Authentication ---- */
    printf(CYAN " ---Welcome To Blood Bank ---\n" RESET);

    if (!credentialsExist())
        firstTimeSetup();

    loginScreen();

    /* ---- Main Program ---- */
    struct Donor d[100];
    int count  = 0;
    int nextID = 1000;
    int choice;
    int found;
    char searchBlood[5];
    int bgChoice, searchChoice;

    count = loadFromFile(d);
    for (int i = 0; i < count; i++)
        if (d[i].id >= nextID) nextID = d[i].id + 1;

    while (1)
    {
        printf(CYAN "\n===== BLOOD BANK MANAGEMENT SYSTEM =====\n" RESET);
        printf(YELLOW "1. Add Donor\n"              RESET);
        printf(YELLOW "2. View Donors\n"             RESET);
        printf(YELLOW "3. Search by Blood Group\n"   RESET);
        printf(YELLOW "4. Delete Donor by ID\n"      RESET);
        printf(YELLOW "5. Update Donor Details\n"    RESET);
        printf(YELLOW "6. Change Password\n"         RESET);
        printf(YELLOW "7. Exit\n"                    RESET);
        printf("\nEnter Choice: ");

        if (scanf("%d", &choice) != 1)
        {
            printf(RED "Invalid input! Numbers only.\n" RESET);
            clearBuffer();
            continue;
        }

        switch (choice)
        {

        /* ---------- ADD DONOR ---------- */
        case 1:
            if (count >= 100)
            {
                printf(RED "\nDatabase Full!\n" RESET);
                break;
            }

            d[count].id = nextID++;

            printf(CYAN "\n===== ADD DONOR =====\n" RESET);
            printf(GREEN "Generated Donor ID: %d\n" RESET, d[count].id);

            while (1)
            {
                int valid = 1;
                printf("Enter Name        : ");
                scanf(" %49[^\n]", d[count].name);
                for (int i = 0; d[count].name[i]; i++)
                    if (!isalpha(d[count].name[i]) && d[count].name[i] != ' ')
                    { valid = 0; break; }
                if (valid) break;
                printf(RED "Invalid Name! Only letters allowed.\n" RESET);
            }

            while (1)
            {
                printf("Enter Age (18-60) : ");
                if (scanf("%d", &d[count].age) != 1)
                {
                    printf(RED "Invalid Input! Numbers only.\n" RESET);
                    clearBuffer();
                    continue;
                }
                if (d[count].age >= 18 && d[count].age <= 60) break;
                printf(RED "Age must be between 18 and 60.\n" RESET);
            }

            printf(CYAN "\nChoose Blood Group\n" RESET);
            printf("1. A+\n2. A-\n3. B+\n4. B-\n5. AB+\n6. AB-\n7. O+\n8. O-\n");

            while (1)
            {
                printf("Enter Choice      : ");
                if (scanf("%d", &bgChoice) != 1)
                {
                    printf(RED "Invalid Input!\n" RESET);
                    clearBuffer();
                    continue;
                }
                if (bgChoice >= 1 && bgChoice <= 8) break;
                printf(RED "Please choose between 1-8.\n" RESET);
            }

            switch (bgChoice)
            {
                case 1: strcpy(d[count].bloodGroup, "A+");  break;
                case 2: strcpy(d[count].bloodGroup, "A-");  break;
                case 3: strcpy(d[count].bloodGroup, "B+");  break;
                case 4: strcpy(d[count].bloodGroup, "B-");  break;
                case 5: strcpy(d[count].bloodGroup, "AB+"); break;
                case 6: strcpy(d[count].bloodGroup, "AB-"); break;
                case 7: strcpy(d[count].bloodGroup, "O+");  break;
                case 8: strcpy(d[count].bloodGroup, "O-");  break;
            }

            while (1)
            {
                printf("Enter Phone       : ");
                scanf("%14s", d[count].phone);
                clearBuffer();
                if (isValidPhone(d[count].phone)) break;
                printf(RED "Invalid Phone! Must be exactly 10 digits and start with 97 or 98.\n" RESET);
            }

            printf("Enter Address     : ");
            fgets(d[count].address, sizeof(d[count].address), stdin);
            d[count].address[strcspn(d[count].address, "\n")] = '\0';

            count++;
            printf(GREEN "\nDonor Added Successfully!\n" RESET);
            printf(CYAN "\n-- Newly Added Donor ---------------------------------------------\n" RESET);
            printTableHeader();
            printTableRow(&d[count - 1]);
            printTableFooter();
            saveToFile(d, count);
            break;

        /* ---------- VIEW ALL ---------- */
        case 2:
            if (count == 0)
            {
                printf(RED "\nNo Donor Records Found!\n" RESET);
                break;
            }
            printf(CYAN "\n-- All Donor Records ---------------------------------------------\n" RESET);
            printTableHeader();
            for (int i = 0; i < count; i++) printTableRow(&d[i]);
            printTableFooter();
            printf(GREEN "  Total Donors: %d\n" RESET, count);
            break;

        /* ---------- SEARCH BY BLOOD GROUP ---------- */
        case 3:
        {
            printf(CYAN "\nChoose Blood Group to Search\n" RESET);
            printf("1. A+\n2. A-\n3. B+\n4. B-\n5. AB+\n6. AB-\n7. O+\n8. O-\n");

            while (1)
            {
                printf("Enter Choice      : ");
                if (scanf("%d", &searchChoice) != 1)
                {
                    printf(RED "Invalid Input!\n" RESET);
                    clearBuffer();
                    continue;
                }
                if (searchChoice >= 1 && searchChoice <= 8) break;
                printf(RED "Please choose between 1-8.\n" RESET);
            }

            switch (searchChoice)
            {
                case 1: strcpy(searchBlood, "A+");  break;
                case 2: strcpy(searchBlood, "A-");  break;
                case 3: strcpy(searchBlood, "B+");  break;
                case 4: strcpy(searchBlood, "B-");  break;
                case 5: strcpy(searchBlood, "AB+"); break;
                case 6: strcpy(searchBlood, "AB-"); break;
                case 7: strcpy(searchBlood, "O+");  break;
                case 8: strcpy(searchBlood, "O-");  break;
            }

            found = 0;
            char searchAddr[100];
            int  filterAddr = 0;
            printf("\nFilter by Address? (Press Enter to skip, or type address keyword): ");
            clearBuffer();
            fgets(searchAddr, sizeof(searchAddr), stdin);
            searchAddr[strcspn(searchAddr, "\n")] = '\0';
            if (strlen(searchAddr) > 0) filterAddr = 1;

            printf(CYAN "\n-- Search Results : Blood Group " RED BOLD "%s" RESET CYAN, searchBlood);
            if (filterAddr)
                printf(" | Address contains: " YELLOW BOLD "%s" RESET CYAN, searchAddr);
            printf(" ---------------------------------\n" RESET);
            printTableHeader();

            for (int i = 0; i < count; i++)
            {
                if (strcmp(d[i].bloodGroup, searchBlood) == 0)
                {
                    if (filterAddr)
                    {
                        char addrLower[100], keyLower[100];
                        int j;
                        for (j = 0; d[i].address[j] && j < 99; j++)
                            addrLower[j] = tolower((unsigned char)d[i].address[j]);
                        addrLower[j] = '\0';
                        for (j = 0; searchAddr[j] && j < 99; j++)
                            keyLower[j] = tolower((unsigned char)searchAddr[j]);
                        keyLower[j] = '\0';
                        if (!strstr(addrLower, keyLower)) continue;
                    }
                    printTableRow(&d[i]);
                    found = 1;
                }
            }

            if (!found)
                printf("  | %-6s | %-26s | %-7s | %-11s | %-12s | %-28s |\n",
                       "--", "No matching donor found", "--", searchBlood, "----------", "----------");

            printTableFooter();
            if (found)
                printf(GREEN "  Donor(s) found with blood group %s\n" RESET, searchBlood);
            else
                printf(RED "  No donor found with blood group %s\n" RESET, searchBlood);
            break;
        }

        /* ---------- DELETE ---------- */
        case 4:
        {
            if (count == 0)
            {
                printf(RED "\nNo Donor Records Found!\n" RESET);
                break;
            }

            int delID;
            printf(CYAN "\n===== DELETE DONOR =====\n" RESET);
            printf("Enter Donor ID to Delete: ");
            if (scanf("%d", &delID) != 1)
            {
                printf(RED "Invalid Input! Numbers only.\n" RESET);
                clearBuffer();
                break;
            }

            int delIdx = -1;
            for (int i = 0; i < count; i++)
                if (d[i].id == delID) { delIdx = i; break; }

            if (delIdx == -1)
            {
                printf(RED "\nDonor with ID %d not found!\n" RESET, delID);
                break;
            }

            printf(YELLOW "\n-- Donor to be Deleted -------------------------------------------\n" RESET);
            printTableHeader();
            printTableRow(&d[delIdx]);
            printTableFooter();

            char confirm;
            printf(RED "\nAre you sure you want to delete this donor? (y/n): " RESET);
            scanf(" %c", &confirm);

            if (confirm == 'y' || confirm == 'Y')
            {
                for (int i = delIdx; i < count - 1; i++) d[i] = d[i + 1];
                count--;
                printf(GREEN "\nDonor ID %d deleted successfully!\n" RESET, delID);
                saveToFile(d, count);
            }
            else
                printf(YELLOW "\nDeletion cancelled.\n" RESET);
            break;
        }

        /* ---------- UPDATE ---------- */
        case 5:
        {
            if (count == 0)
            {
                printf(RED "\nNo Donor Records Found!\n" RESET);
                break;
            }

            int updID;
            printf(CYAN "\n===== UPDATE DONOR DETAILS =====\n" RESET);
            printf("Enter Donor ID to Update: ");
            if (scanf("%d", &updID) != 1)
            {
                printf(RED "Invalid Input! Numbers only.\n" RESET);
                clearBuffer();
                break;
            }

            int updIdx = -1;
            for (int i = 0; i < count; i++)
                if (d[i].id == updID) { updIdx = i; break; }

            if (updIdx == -1)
            {
                printf(RED "\nDonor with ID %d not found!\n" RESET, updID);
                break;
            }

            printf(CYAN "\n-- Current Details -----------------------------------------------\n" RESET);
            printTableHeader();
            printTableRow(&d[updIdx]);
            printTableFooter();

            int updChoice;
            printf(CYAN "\nWhat would you like to update?\n" RESET);
            printf(YELLOW "1. Name\n2. Age\n3. Blood Group\n4. Phone\n5. Address\n6. All Fields\n" RESET);
            printf("Enter Choice: ");

            if (scanf("%d", &updChoice) != 1 || updChoice < 1 || updChoice > 6)
            {
                printf(RED "Invalid Choice!\n" RESET);
                clearBuffer();
                break;
            }

            if (updChoice == 1 || updChoice == 6)
            {
                while (1)
                {
                    int valid = 1;
                    printf("Enter New Name        : ");
                    scanf(" %49[^\n]", d[updIdx].name);
                    for (int i = 0; d[updIdx].name[i]; i++)
                        if (!isalpha(d[updIdx].name[i]) && d[updIdx].name[i] != ' ')
                        { valid = 0; break; }
                    if (valid) break;
                    printf(RED "Invalid Name! Only letters allowed.\n" RESET);
                }
            }

            if (updChoice == 2 || updChoice == 6)
            {
                while (1)
                {
                    printf("Enter New Age (18-60) : ");
                    if (scanf("%d", &d[updIdx].age) != 1)
                    {
                        printf(RED "Invalid Input!\n" RESET);
                        clearBuffer();
                        continue;
                    }
                    if (d[updIdx].age >= 18 && d[updIdx].age <= 60) break;
                    printf(RED "Age must be between 18 and 60.\n" RESET);
                }
            }

            if (updChoice == 3 || updChoice == 6)
            {
                int bgUpd;
                printf(CYAN "Choose New Blood Group\n" RESET);
                printf("1. A+\n2. A-\n3. B+\n4. B-\n5. AB+\n6. AB-\n7. O+\n8. O-\n");
                while (1)
                {
                    printf("Enter Choice          : ");
                    if (scanf("%d", &bgUpd) != 1)
                    {
                        printf(RED "Invalid Input!\n" RESET);
                        clearBuffer();
                        continue;
                    }
                    if (bgUpd >= 1 && bgUpd <= 8) break;
                    printf(RED "Please choose between 1-8.\n" RESET);
                }
                switch (bgUpd)
                {
                    case 1: strcpy(d[updIdx].bloodGroup, "A+");  break;
                    case 2: strcpy(d[updIdx].bloodGroup, "A-");  break;
                    case 3: strcpy(d[updIdx].bloodGroup, "B+");  break;
                    case 4: strcpy(d[updIdx].bloodGroup, "B-");  break;
                    case 5: strcpy(d[updIdx].bloodGroup, "AB+"); break;
                    case 6: strcpy(d[updIdx].bloodGroup, "AB-"); break;
                    case 7: strcpy(d[updIdx].bloodGroup, "O+");  break;
                    case 8: strcpy(d[updIdx].bloodGroup, "O-");  break;
                }
            }

            if (updChoice == 4 || updChoice == 6)
            {
                while (1)
                {
                    printf("Enter New Phone       : ");
                    scanf("%14s", d[updIdx].phone);
                    clearBuffer();
                    if (isValidPhone(d[updIdx].phone)) break;
                    printf(RED "Invalid Phone! Must be exactly 10 digits and start with 97 or 98.\n" RESET);
                }
            }

            if (updChoice == 5 || updChoice == 6)
            {
                printf("Enter New Address     : ");
                if (updChoice == 5) clearBuffer();
                fgets(d[updIdx].address, sizeof(d[updIdx].address), stdin);
                d[updIdx].address[strcspn(d[updIdx].address, "\n")] = '\0';
            }

            printf(GREEN "\nDonor Updated Successfully!\n" RESET);
            printf(CYAN "\n-- Updated Details -----------------------------------------------\n" RESET);
            printTableHeader();
            printTableRow(&d[updIdx]);
            printTableFooter();
            saveToFile(d, count);
            break;
        }

        /* ---------- CHANGE PASSWORD ---------- */
        case 6:
            changePassword();
            break;

        /* ---------- EXIT ---------- */
        case 7:
            printf(GREEN "\nExiting Program... Goodbye!\n\n" RESET);
            exit(0);

        default:
            printf(RED "\nInvalid Choice! Please choose 1 - 7.\n" RESET);
        }
    }

    return 0;
}
