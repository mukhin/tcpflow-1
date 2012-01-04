#ifndef FLOW_H
#define FLOW_H

/*
 * flow.h
 * defines the basic classes used by the tcpflow program.
 */


class ipaddr {
public:;
    ipaddr(){
	memset(addr,0,sizeof(addr));
    }
    ipaddr(const in_addr_t &a){
	*(in_addr_t *)addr = a;
	memset(addr+4,0,12);
    }
    ipaddr(const uint8_t a[16]){
	memcpy(addr,a,16);
    }

    u_int8_t addr[16];			// holds v4 or v16
    inline bool operator ==(const ipaddr &b) const{
	return 	memcmp(this->addr,b.addr,sizeof(addr))==0;
    };
    inline bool operator <=(const ipaddr &b) const{
	return 	memcmp(this->addr,b.addr,sizeof(addr))<=0;
    };
    inline bool operator >(const ipaddr &b) const{
	return 	memcmp(this->addr,b.addr,sizeof(addr))>0;
    };
    inline bool operator >=(const ipaddr &b) const{
	return 	memcmp(this->addr,b.addr,sizeof(addr))>=0;
    };

    inline bool operator <(const ipaddr &b) const {
	return  memcmp(this->addr,b.addr,sizeof(this->addr))<0;
    }

};

inline std::ostream & operator <<(std::ostream &os,const ipaddr &b)  {
	os << (int)b.addr[12] << "." << (int)b.addr[13] << "." << (int)b.addr[14] << "." << (int)b.addr[15];
	return os;
    }

inline bool operator ==(const struct timeval &a,const struct timeval &b) {
    return a.tv_sec==b.tv_sec && a.tv_usec==b.tv_usec;
}

inline bool operator <(const struct timeval &a,const struct timeval &b) {
    return (a.tv_sec<b.tv_sec) || ((a.tv_sec==b.tv_sec) && (a.tv_sec<b.tv_sec));
}

/*
 * describes the TCP flow without the timing information
 */
class flow_addr {
public:
    flow_addr():src(),dst(),sport(0),dport(0),family(0){
    }
    flow_addr(const flow_addr &f):src(f.src),dst(f.dst),sport(f.sport),dport(f.dport),family(f.family){
    }
    virtual ~flow_addr(){};
    ipaddr	src;			// Source IP address; holds v4 or v6 
    ipaddr	dst;			// Destination IP address; holds v4 or v6 
    u_int16_t sport;			// Source port number 
    u_int16_t dport;			// Destination port number 
    sa_family_t family;			// AF_INET or AF_INET6 */

    inline bool operator ==(const flow_addr &b) const {
	return this->src==b.src &&
	    this->dst==b.dst &&
	    this->sport==b.sport &&
	    this->dport==b.dport &&
	    this->family==b.family;
    }

    inline std::ostream & operator <<(std::ostream &os) const {
	os << "flow[" << this->src << ":" << this->sport << "->" << this->dst << ":" << this->dport << "]";
	return os;
    }

    inline bool operator <(const flow_addr &b) const {
	if (this->src<b.src) return true;
	if (this->src>b.src) return false;
	if (this->dst<b.dst) return true;
	if (this->dst>b.dst) return false;
	if (this->sport<b.sport) return true;
	if (this->sport>b.sport) return false;
	if (this->dport<b.dport) return true;
	if (this->dport>b.dport) return false;
	if (this->family < b.family) return true;
	if (this->family > b.family) return true;
	return false;    /* they are equal! */
    }
};

/*
 * A flow is a flow_addr that has additional information regarding when it was seen
 * and how many packets were seen. The address is used to locate the flow in the array.
 */
class flow_t : public flow_addr {
public:;
    static int32_t NO_VLAN;			/* vlan flag for no vlan */
    flow_t():id(),vlan(),tstart(),tlast(),packet_count(),connection_count(){};
    flow_t(const flow_addr &flow_addr_,int32_t vlan_,const struct timeval &t1,const struct timeval &t2,uint64_t id_,uint64_t connection_count_):
	flow_addr(flow_addr_),id(id_),vlan(vlan_),tstart(t1),tlast(t2),packet_count(0),connection_count(connection_count_){}
    virtual ~flow_t(){};
    uint64_t id;			// flow_counter when this flow was created
    int32_t	vlan;			// vlan interface we observed; -1 means no vlan 
    struct timeval tstart;		// when first seen
    struct timeval tlast;		// when last seen
    uint64_t packet_count;			// packet count
    uint64_t connection_count;	// how many times have we seen a flow with the same addr?
    std::string filename();		// returns filename for a flow
};

/*
 * Convenience class for working with TCP headers
 */
class tcp_header_t {
public:
    tcp_header_t(const u_char *data):
	tcp_header((struct tcphdr *)data){};
    tcp_header_t(const tcp_header_t &b):
	tcp_header(b.tcp_header){}
    tcp_header_t &operator=(const tcp_header_t &that) {
	this->tcp_header = that.tcp_header;
	return *this;
    }

    virtual ~tcp_header_t(){}
    struct tcphdr *tcp_header;
    size_t tcp_header_len(){ return tcp_header->th_off * 4; }
    uint16_t sport() {return ntohs(tcp_header->th_sport);}
    uint16_t dport() {return ntohs(tcp_header->th_dport);}
    tcp_seq  seq()   {return ntohl(tcp_header->th_seq);}
    bool th_fin()    {return tcp_header->th_flags & TH_FIN;}
    bool th_ack()    {return tcp_header->th_flags & TH_ACK;}
    bool th_syn()    {return tcp_header->th_flags & TH_SYN;}
    
};


/*
 * The information that tcpflow uses to represent each flow
 */
class tcpip {
private:
    class not_impl: public std::exception {
	virtual const char *what() const throw() {
	    return "copying tcpip objects is not implemented.";
	}
    };
    tcpip(const tcpip &t):flow(),isn(),flow_pathname(),fp(),pos(),last_access(),
				    bytes_printed(),fin(),
				    finished(),file_exists(),dir_sc(),dir_cs(){
	throw new not_impl();
    }
    tcpip &operator=(const tcpip &that) {
	throw new not_impl();
    }
public:;

    /* the flow database */
    static uint64_t flow_counter;	// how many flows have we seen?
    static tcpip *create_tcpip(const flow_addr &flow, int32_t vlan,tcp_seq isn,const timeval &ts,uint64_t connection_count);
    static tcpip *find_tcpip(const flow_addr &flow);
    static void remove_tcpip(const flow_addr &flow);
    static void process_tcp(const struct timeval *ts,const u_char *data, u_int32_t length,
			    const ipaddr &src, const ipaddr &dst,int32_t vlan,sa_family_t family);

    /* constructors */
    tcpip(const flow_t &flow_,tcp_seq isn_);
    virtual ~tcpip(){};
    flow_t flow;			/* Description of this flow */
    tcp_seq isn;			// Flow's initial sequence number
    std::string flow_pathname;		// path where flow is stored
    FILE *fp;			/* Pointer to file storing this flow's data */
    long pos;			/* Current write position in fp */
    int last_access;		/* "Time" of last access; used to sort the open flows to figure out which to close */
    uint64_t bytes_printed;		// for -b and -c used together
    bool fin;				// received a FIN flag
    bool finished;
    bool file_exists;
    bool dir_sc;			// server to client
    bool dir_cs;			// client to server
    FILE *attempt_fopen(const char *filename);
    FILE *open_file();			// opens this file and returns it
    int close_file();
    void print_packet(const u_char *data, u_int32_t length);
    void store_packet(const u_char *data, u_int32_t length, u_int32_t seq, int syn_set);

};

inline std::ostream & operator <<(std::ostream &os,const tcpip &f) {
    //os << "tcpip[" << f.flow << " isn:" << f.isn << " pos:" << f.pos << "]";
    return os;
}




#endif
