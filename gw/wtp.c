/*
 * wtp.c - WTP implementation
 *
 * WTP state machines are stored in the project library data sructure list. 
 * Segments to be reassembled are stored as ordered linked list. 
 *
 * By Aarno Syvänen for WapIT Ltd.
 */

#include "wtp.h" 

/*
 * Possible errors in incoming messages.
 */
enum {
    no_datagram,
    wrong_version,
    illegal_header,
    no_segmentation,
    pdu_too_short_error,
    no_concatenation
};

/*
 * Protocol version (currently, there is only one)
 */
enum {
   CURRENT = 0x00
};

/*
 * Abort types (i.e., provider abort codes defined by WAP)
 */
enum {
   UNKNOWN = 0x00,
   PROTOERR = 0x01,
   INVALIDTID = 0x02,
   NOTIMPLEMENTEDCL2 = 0x03,
   NOTIMPLEMENTEDSAR = 0x04,
   NOTIMPLEMENTEDUACK = 0x05,
   WTPVERSIONZERO = 0x06,
   CAPTEMPEXCEEDED = 0x07,
   NORESPONSE = 0x08,
   MESSAGETOOLARGE = 0x09
};    

/*
 * Global data structuresc:
 *
 * wtp machines list
 */

static List *machines = NULL;

/*
 * Global WTP transaction identifier and its lock (this is used by WSP when it 
 * wants to start a new transaction)
 */

static unsigned long wtp_tid = 0;

Mutex *wtp_tid_lock = NULL;

/*****************************************************************************
 *
 * Prototypes of internal functions:
 *
 * Create an uniniatilized wtp state machine.
 */

static WTPMachine *wtp_machine_create_empty(void);
static void wtp_machine_destroy(WTPMachine *sm);


/*
 * Print a wtp event or a wtp machine state name as a string.
 */

static unsigned char *name_state(int name);

/*
 * Find the WTPMachine from the global list of WTPMachine structures that
 * corresponds to the five-tuple of source and destination addresses and
 * ports and the transaction identifier. Return a pointer to the machine,
 * or NULL if not found.
 */
static WTPMachine *wtp_machine_find(Octstr *source_address, long source_port,
	Octstr *destination_address, long destination_port, long tid);

/*
 * Packs a wsp event. Fetches flags and user data from a wtp event. Address 
 * five-tuple and tid are fields of the wtp machine.
 */
static WAPEvent *pack_wsp_event(WAPEventName wsp_name, WAPEvent *wtp_event, 
         WTPMachine *machine);

static void append_to_event_queue(WTPMachine *machine, WAPEvent *event);
 
static WAPEvent *remove_from_event_queue(WTPMachine *machine);

static long deduce_tid(Msg *msg);
static unsigned char deduce_pdu_type(unsigned char octet);

static int protocol_version(unsigned char octet);

static WAPEvent *unpack_ack(long tid, unsigned char octet);

static WAPEvent *unpack_abort(Msg *msg, long tid, unsigned char first_octet, 
                              unsigned char fourth_octet);

static WAPEvent *unpack_invoke(Msg *msg, long tid, 
       unsigned char first_octet, unsigned char fourth_octet);

static WAPEvent *tell_about_error(int type, WAPEvent *event, Msg *msg, long tid);
static WAPEvent *unpack_invoke_flags(WAPEvent *event, Msg *msg, long tid, 
       unsigned char first_octet, unsigned char fourth_octet);

static Address *deduce_reply_address(Msg *msg);

/******************************************************************************
 *
 * EXTERNAL FUNCTIONS:
 */

/*
 * Mark a WTP state machine unused. Normal functions do not remove machines, just 
 * set a flag. In addition, destroys the timer.
 */
void wtp_machine_mark_unused(WTPMachine *machine) {
     machine->in_use = 0;
     wtp_timer_destroy(machine->timer);
     machine->timer = NULL;
}

/*
 * Write state machine fields, using debug function from a project library 
 * wapitlib.c.
 */
void wtp_machine_dump(WTPMachine *machine){
 
       if (machine != NULL){

           debug("wap.wtp", 0, "WTPMachine %p: dump starting", (void *) machine); 
	   #define INTEGER(name) \
	           debug("wap.wtp", 0, "  %s: %ld", #name, machine->name)
           #define MSG(name) \
                   debug("wap.wtp", 0, "Field %s: ", #name); \
                   msg_dump(machine->name, 1)
           #define WSP_EVENT(name) \
                   debug("wap.wtp", 0, "WSP event %s:", #name); \
                   wap_event_dump(machine->name)
           #define ENUM(name) debug("wap.wtp", 0, "  state = %s.", name_state(machine->name))
	   #define OCTSTR(name)  \
	   	debug("wap.wtp", 0, "  Octstr field %s :", #name); \
                octstr_dump(machine->name, 1)
           #define TIMER(name)   debug("wap.wtp", 0, "  Machine timer %p:", (void *) \
                                       machine->name)
           #define MUTEX(name)   if (mutex_try_lock(machine->name) == -1) \
                                    debug("wap.wtp", 0, "%s locked", #name);\
                                 else {\
                                    debug("wap.wtp", 0, "%s unlocked", #name);\
                                    mutex_unlock(machine->name);\
                                 }
           #define NEXT(name) 
	   #define MACHINE(field) field
	   #define LIST(name) \
	           debug("wap.wtp", 0, "  %s %s", #name, \
		   machine->name ? "non-NULL" : "NULL")
	   #include "wtp_machine-decl.h"
           debug("wap.wtp", 0, "WTPMachine dump ends");
	
	} else {
           debug("wap.wtp", 0, "WTP: dump: machine does not exist");
        }
}


WTPMachine *wtp_machine_find_or_create(Msg *msg, WAPEvent *event){

          WTPMachine *machine = NULL;
          long tid;
	  Octstr *src_addr, *dst_addr;
	  long src_port, dst_port;

	  tid = -1;
	  src_addr = NULL;
	  dst_addr = NULL;
	  src_port = -1;
	  dst_port = -1;

          switch (event->type){

	          case RcvInvoke:
                       tid = event->RcvInvoke.tid;
		       src_addr = event->RcvInvoke.client_address;
		       src_port = event->RcvInvoke.client_port;
		       dst_addr = event->RcvInvoke.server_address;
		       dst_port = event->RcvInvoke.server_port;
                  break;

	          case RcvAck:
                       tid = event->RcvAck.tid;
                  break;

	          case RcvAbort:
                       tid = event->RcvAbort.tid;
                  break;

	          case RcvErrorPDU:
                       tid = event->RcvErrorPDU.tid;
                  break;

                  default:
                       debug("wap.wtp", 0, "WTP: machine_find_or_create: unhandled event"); 
                       wap_event_dump(event);
                       return NULL;
                  break;
	   }

	   if (src_addr == NULL) {
		   src_addr = msg->wdp_datagram.source_address;
		   dst_addr = msg->wdp_datagram.destination_address;
		   src_port = msg->wdp_datagram.source_port;
		   dst_port = msg->wdp_datagram.destination_port;
	   }

           machine = wtp_machine_find(src_addr, src_port, dst_addr, dst_port,
                    		tid);
           
           if (machine == NULL){

              switch (event->type){
/*
 * When PDU with an illegal header is received, its tcl-field is irrelevant (and possibly 
 * meaningless).
 */
	              case RcvInvoke: case RcvErrorPDU:
	                   machine = wtp_machine_create(
                                     src_addr, src_port, 
				     dst_addr, dst_port,
				     tid, event->RcvInvoke.tcl);
                           machine->in_use = 1;
                      break;

	              case RcvAck: 
			   info(0, "WTP: machine_find_or_create: ack received, yet having no machine");
                      break;

                      case RcvAbort: 
			   info(0, "WTP: machine_find_or_create: abort received, yet having no machine");
                      break;
                 
	              default:
                           debug("wap.wtp", 0, "WTP: machine_find_or_create: unhandled event");
                           wap_event_dump(event);
                           return NULL;
                      break;
              }
	   }
           
           return machine;
}

/*
 * Transfers data from fields of a message to fields of WTP event. User data has
 * the host byte order. Updates the log and sends protocol error messages. Reassembles 
 * segmented messages, too.
 *
 * First empty instance of segment_lists is created by wapbox.c. This function allocates 
 * and deallocates memory for its member lists. After deallocation a new instance of an 
 * empty segments data structure is creted. For result, an wtp event is created, if 
 * appropiate. The memory for this data structure is deallocated either by this module, if 
 * its data is added to a message to be reassembled, or by wtp_handle_event.
 *
 * Return event, when we have a single message or have reassembled whole the message; NULL, 
 * when we have a segment inside of a segmented message.
 */
WAPEvent *wtp_unpack_wdp_datagram(Msg *msg){

         WAPEvent *event = NULL;

         unsigned char first_octet,
                  pdu_type;
         int fourth_octet;              /* if error, -1 is stored into this variable */
 
         long tid = 0;
         
         tid = deduce_tid(msg);

         if (octstr_len(msg->wdp_datagram.user_data) < 3){
            event = tell_about_error(pdu_too_short_error, event, msg, tid);
            debug("wap.wtp", 0, "Got too short PDU (less than three octets)");
            msg_dump(msg, 0);
            return event;
         }

         first_octet = octstr_get_char(msg->wdp_datagram.user_data, 0);
         pdu_type = deduce_pdu_type(first_octet);

         switch (pdu_type){
/*
 * Message type cannot be result, because we are a server.
 */
                case ERRONEOUS: case RESULT: case SEGMENTED_RESULT:
                     event = tell_about_error(illegal_header, event, msg, tid);
                     return event;
                break;
/*
 * "Not allowed" means (when specification language is applied) concatenated PDUs.
 */
                case NOT_ALLOWED:
                     event = tell_about_error(no_concatenation, event, msg, tid);
                     return event;
                break;
/*
 * Invoke PDU is used by first segment of a segmented message, too. 
 */       
	       case INVOKE:
                     fourth_octet = octstr_get_char(msg->wdp_datagram.user_data, 3);

                     if (fourth_octet == -1){
                         event = tell_about_error(pdu_too_short_error, event, msg, tid);
                         debug("wap.wtp", 0, "WTP: unpack_datagram; missing fourth octet (invoke)");
                         msg_dump(msg, 0);
                         return event;
                     }
                     
                     event = unpack_invoke(msg, tid, first_octet, 
                                           fourth_octet);

		     return event;
               break;

               case ACK:
		    return unpack_ack(tid, first_octet);   
               break;

	       case ABORT:

                    fourth_octet = octstr_get_char(msg->wdp_datagram.user_data, 3);

                    if (fourth_octet == -1){
                       event = tell_about_error(pdu_too_short_error, event, msg, tid);
                       debug("wap.wtp", 0, "WTP: unpack_datagram; missing fourth octet (abort)");
                       msg_dump(msg, 0);
                       return event;
                    }

                    return unpack_abort(msg, tid, first_octet, fourth_octet);
               break;
         } /* switch */
/* Following return is unnecessary but required by the compiler */
         return NULL;
} /* function */

/*
 * Feed an event to a WTP state machine. Handle all errors yourself, do not
 * report them to the caller. Note: Do not put {}s of the else block inside
 * the macro definition (it ends with a line without a backlash). 
 */
void wtp_handle_event(WTPMachine *machine, WAPEvent *event){
     WAPEventName current_primitive;
     WAPEvent *wsp_event = NULL;
     WAPEvent *timer_event = NULL;

/* 
 * If we're already handling events for this machine, add the event to the 
 * queue.
 */
     if (mutex_try_lock(machine->mutex) == -1) {
	append_to_event_queue(machine, event);
	return;
     }

     do {
	  debug("wap.wtp", 0, "WTP: machine %p, state %s, event %s.", 
	  	(void *) machine, 
		name_state(machine->state), 
		wap_event_name(event->type));

	  #define STATE_NAME(state)
	  #define ROW(wtp_state, event_type, condition, action, next_state) \
		  if (machine->state == wtp_state && \
		     event->type == event_type && \
		     (condition)) { \
		     action \
                     machine->state = next_state; \
		  } else 
	  #include "wtp_state-decl.h"
		  {
		     error(0, "WTP: handle_event: unhandled event!");
		     debug("wap.wtp", 0, "WTP: handle_event: Unhandled event was:");
		     wap_event_dump(event);
                     return;
		  }

	  if (event != NULL) {
	     wap_event_destroy(event);  
          }

          event = remove_from_event_queue(machine);
     } while (event != NULL);
     
     if (machine->in_use)
	mutex_unlock(machine->mutex);
     else
     	wtp_machine_destroy(machine);
 
     return;
}

unsigned long wtp_tid_next(void){
     
     mutex_lock(wtp_tid_lock);
     ++wtp_tid;
     mutex_unlock(wtp_tid_lock);

     return wtp_tid;
} 


void wtp_init(void) {
     machines = list_create();
     wtp_tid_lock = mutex_create();
}

void wtp_shutdown(void) {
     debug("wap.wtp", 0, "wtp_shutdown: %ld machines left",
     	   list_len(machines));
     while (list_len(machines) > 0)
	wtp_machine_destroy(list_extract_first(machines));
     list_destroy(machines);
     mutex_destroy(wtp_tid_lock);
}

/*****************************************************************************
 *
 * INTERNAL FUNCTIONS:
 *
 * Give the name of an event in a readable form. 
 */

static unsigned char *name_state(int s){

       switch (s){
              #define STATE_NAME(state) case state: return #state;
              #define ROW(state, event, condition, action, new_state)
              #include "wtp_state-decl.h"
              default:
                      return "unknown state";
       }
}


/*
 *  We are interested only machines in use, it is, having in_use-flag 1. Transaction
 *  is identified by the address four-tuple and tid.
 */
struct machine_pattern {
	Octstr *source_address;
	long source_port;
	Octstr *destination_address;
	long destination_port;
	long tid;
};

static int is_wanted_machine(void *a, void *b) {
	struct machine_pattern *pat;
	WTPMachine *m;
	
	m = a;
	pat = b;

	return octstr_compare(m->source_address, pat->source_address) == 0 &&
               m->source_port == pat->source_port && 
               octstr_compare(m->destination_address, 
	                      pat->destination_address) == 0 &&
               m->destination_port == pat->destination_port &&
	       m->tid == pat->tid && 
	       m->in_use == 1;
}

static WTPMachine *wtp_machine_find(Octstr *source_address, long source_port,
       Octstr *destination_address, long destination_port, long tid){
	struct machine_pattern pat;
	WTPMachine *m;
	
	pat.source_address = source_address;
	pat.source_port = source_port;
	pat.destination_address = destination_address;
	pat.destination_port = destination_port;
	pat.tid = tid;
	
	m = list_search(machines, &pat, is_wanted_machine);
	return m;
}

/*
 * Iniatilizes wtp machine and adds it to machines list. 
 */
static WTPMachine *wtp_machine_create_empty(void){
       WTPMachine *machine = NULL;

        machine = gw_malloc(sizeof(WTPMachine));
        
        #define INTEGER(name) machine->name = 0
        #define ENUM(name) machine->name = LISTEN
        #define MSG(name) machine->name = msg_create(wdp_datagram)
        #define OCTSTR(name) machine->name = NULL
        #define WSP_EVENT(name) machine->name = NULL
        #define MUTEX(name) machine->name = mutex_create()
        #define TIMER(name) machine->name = wtp_timer_create()
        #define NEXT(name) machine->name = NULL
        #define MACHINE(field) field
	#define LIST(name) machine->name = list_create()
        #include "wtp_machine-decl.h"

	list_append(machines, machine);

        return machine;
}

/*
 * Destroys a WTPMachine. Assumes it is safe to do so. Assumes it has already
 * been deleted from the machines list.
 */
static void wtp_machine_destroy(WTPMachine *machine){
	list_delete_equal(machines, machine);
        #define INTEGER(name) machine->name = 0
        #define ENUM(name) machine->name = LISTEN
        #define MSG(name) msg_destroy(machine->name)
        #define OCTSTR(name) octstr_destroy(machine->name)
        #define WSP_EVENT(name) machine->name = NULL
        #define MUTEX(name) mutex_destroy(machine->name)
        #define TIMER(name) wtp_timer_destroy(machine->name)
        #define NEXT(name) machine->name = NULL
        #define MACHINE(field) field
	#define LIST(name) list_destroy(machine->name)
        #include "wtp_machine-decl.h"
	gw_free(machine);
}

/*
 * Create a new WTPMachine for a given transaction, identified by the five-tuple 
 * in the arguments. In addition, update the transaction class field of the 
 * machine. If machines list is busy, just wait.
 */
WTPMachine *wtp_machine_create(Octstr *source_address, 
           long source_port, Octstr *destination_address, 
           long destination_port, long tid, long tcl) {

	   WTPMachine *machine = NULL;
	   
           machine = wtp_machine_create_empty();

           machine->source_address = octstr_duplicate(source_address);
           machine->source_port = source_port;
           machine->destination_address = octstr_duplicate(destination_address);
           machine->destination_port = destination_port;
           machine->tid = tid;
           machine->tcl = tcl;

           return machine;
} 

/*
 * Packs a wsp event. Fetches flags and user data from a wtp event. Address 
 * five-tuple and tid are fields of the wtp machine.
 */
static WAPEvent *pack_wsp_event(WAPEventName wsp_name, WAPEvent *wtp_event, 
         WTPMachine *machine){

         WAPEvent *event = wap_event_create(wsp_name);

         switch (wsp_name){
                
	        case TR_Invoke_Ind:
                     event->TR_Invoke_Ind.ack_type = machine->u_ack;
                     event->TR_Invoke_Ind.user_data =
                            octstr_duplicate(wtp_event->RcvInvoke.user_data);
                     event->TR_Invoke_Ind.tcl = wtp_event->RcvInvoke.tcl;
                     event->TR_Invoke_Ind.wsp_tid = wtp_tid_next();
                     event->TR_Invoke_Ind.machine = machine;
                break;

	        case TR_Invoke_Cnf:
                     event->TR_Invoke_Cnf.wsp_tid =
                            event->TR_Invoke_Ind.wsp_tid;
                     event->TR_Invoke_Cnf.machine = machine;
                break;
                
	        case TR_Result_Cnf:
                     event->TR_Result_Cnf.exit_info =
                            octstr_duplicate(wtp_event->RcvInvoke.exit_info);
                     event->TR_Result_Cnf.exit_info_present =
                            wtp_event->RcvInvoke.exit_info_present;
                     event->TR_Result_Cnf.wsp_tid =
                            event->TR_Invoke_Ind.wsp_tid;
                     event->TR_Result_Cnf.machine = machine;
                break;

	        case TR_Abort_Ind:
                     event->TR_Abort_Ind.abort_code =
                            wtp_event->RcvAbort.abort_reason;
                     event->TR_Abort_Ind.wsp_tid =
                            event->TR_Invoke_Ind.wsp_tid;
                     event->TR_Abort_Ind.machine = machine;
                break;
                
	        default:
                break;
         }

         return event;
} 

/*
 * Append an event to the event queue of a WTPMachine. 
 */
static void append_to_event_queue(WTPMachine *machine, WAPEvent *event) {

       list_append(machine->event_queue, event);
}


/*
 * Return the first event from the event queue of a WTPMachine, and remove
 * it from the queue, NULL if the queue was empty.
 */
static WAPEvent *remove_from_event_queue(WTPMachine *machine) {

       return list_extract_first(machine->event_queue);
}

/*
 * Every message type uses the second and the third octets for tid. Bytes are 
 * already in host order. Note that the iniator turns the first bit off, so we do
 * have a genuine tid.
 */
static long deduce_tid(Msg *msg){
   
       long first_part,
            second_part,
            tid;

       first_part = octstr_get_char(msg->wdp_datagram.user_data, 1);
       second_part = octstr_get_char(msg->wdp_datagram.user_data, 2);
       tid = first_part;
       tid = (tid<<8) + second_part; 

       return tid;
}

static unsigned char deduce_pdu_type(unsigned char octet){

       int type;

       if ((type = octet>>3&15) > 7){
          return -1;
       } else {
          return type; 
       }
}

static int protocol_version(unsigned char octet){

       return octet>>6&3;
}

static WAPEvent *unpack_ack(long tid, unsigned char octet){

      WAPEvent *event = NULL;
      unsigned char this_octet;

      event = wap_event_create(RcvAck);

      event->RcvAck.tid = tid;
      this_octet = octet;
      event->RcvAck.tid_ok = this_octet>>2&1;
      this_octet = octet;
      event->RcvAck.rid = this_octet&1;

      return event;
}

WAPEvent *unpack_abort(Msg *msg, long tid, unsigned char first_octet, unsigned 
                       char fourth_octet){

         WAPEvent *event = NULL;
         unsigned char abort_type;      

         event = wap_event_create(RcvAbort);

         abort_type = first_octet&7;
/*
 * Counting of abort types starts at zero.
 */
	 if (abort_type > NUMBER_OF_ABORT_TYPES-1 || 
             fourth_octet > NUMBER_OF_ABORT_REASONS-1){
            event = tell_about_error(illegal_header, event, msg, tid);
            return event;
         }
                
         event->RcvAbort.tid = tid;  
         event->RcvAbort.abort_type = abort_type;   
         event->RcvAbort.abort_reason = fourth_octet;
         debug("wap.wtp", 0, "WTP: unpack_abort: abort event packed");
         return event;
}

/*
 * Fields of an unsegmented invoke are transferred to WAPEvent having type 
 * RcvInvoke.
 *
 * A segmented message is indicated by a cleared ttr flag. This causes the protocol
 * to add the received segment to the message identified by tid. Invoke message has 
 * an implicit sequence number 0 (it being the first segment).
 */
WAPEvent *unpack_invoke(Msg *msg, long tid, 
                        unsigned char first_octet, unsigned char fourth_octet){

         WAPEvent *event = NULL;

         if (protocol_version(fourth_octet) != CURRENT){
            event = tell_about_error(wrong_version, event, msg, tid);
            debug("wap.wtp", 0, "WTP: unpack_invoke: handling version error");
            return event;
         }

         event = wap_event_create(RcvInvoke);
/*
 * First invoke message includes all event flags, even when we are receiving a 
 * segmented message. So we first fetch event flags, and then handle user_data 
 * differently: if message was unsegmented, we transfer all data to event; if it
 * was segmented, we begin reassembly.
 */
         event = unpack_invoke_flags(event, msg, tid, first_octet, fourth_octet);
         octstr_delete(msg->wdp_datagram.user_data, 0, 4);
 
	 event->RcvInvoke.user_data = 
	 	octstr_duplicate(msg->wdp_datagram.user_data); 
	
	 event->RcvInvoke.client_address = 
	 	octstr_duplicate(msg->wdp_datagram.source_address);
	 event->RcvInvoke.server_address = 
	 	octstr_duplicate(msg->wdp_datagram.destination_address);
	 event->RcvInvoke.client_port = msg->wdp_datagram.source_port;
	 event->RcvInvoke.server_port = msg->wdp_datagram.destination_port;
         return event;
}

/*
 * Returns event RcvErrorPDU, when the error is an illegal header, otherwise NULL.
 */
static WAPEvent *tell_about_error(int type, WAPEvent *event, Msg *msg, long tid){

       Address *address = NULL;

       address = deduce_reply_address(msg);
       msg_destroy(msg);
       debug("wap.wtp", 0, "WTP: tell:");
       wtp_send_address_dump(address);

       switch (type){
/*
 * Sending  Abort(WTPVERSIONZERO)
 */
              case wrong_version:
                   gw_free(event);
                   wtp_do_not_start(PROVIDER, WTPVERSIONZERO, address, tid);
                   error(0, "WTP: Version not supported");
              return NULL;
/*
 * Sending  Abort(NOTIMPLEMENTEDSAR)
 */
              case no_segmentation:
                   gw_free(event);
                   wtp_do_not_start(PROVIDER, NOTIMPLEMENTEDSAR, address, tid);
                   error(0, "WTP: No segmentation implemented");
              return NULL;
/*
 * Illegal headers are events, because their handling depends on the protocol state. 
 */
             case illegal_header:
                  error(0, "WTP: Illegal header structure");
                  gw_free(event);
                  event = wap_event_create(RcvErrorPDU);
                  event->RcvErrorPDU.tid = tid;
             return event;

             case pdu_too_short_error:
                  error(0, "WTP: PDU too short");
                  gw_free(event);
                  event = wap_event_create(RcvErrorPDU);
                  event->RcvErrorPDU.tid = tid;
             return event;

             case no_datagram: 
                  error(0, "WTP: No datagram received");
                  gw_free(event);
                  event = wap_event_create(RcvErrorPDU);
                  event->RcvErrorPDU.tid = tid;
             return event;

             case no_concatenation:
                  wtp_do_not_start(PROVIDER, UNKNOWN, address, tid);
                  error(0, "WTP: No concatenation supported");
                  gw_free(event);
             return NULL;
     }
/* Following return is unnecessary but required by the compiler */
     return NULL;
}

static WAPEvent *unpack_invoke_flags(WAPEvent *event, Msg *msg, long tid, 
                unsigned char first_octet, unsigned char fourth_octet){

         unsigned char this_octet,
                       tcl;

         this_octet = fourth_octet;

         tcl = this_octet&3; 
         if (tcl > NUMBER_OF_TRANSACTION_CLASSES-1){
            event = tell_about_error(illegal_header, event, msg, tid);
            return event;
         }

         event->RcvInvoke.tid = tid;
         event->RcvInvoke.rid = first_octet&1;
         this_octet = fourth_octet;               
         event->RcvInvoke.tid_new = this_octet>>5&1;
         this_octet = fourth_octet;
         event->RcvInvoke.up_flag = this_octet>>4&1;
         this_octet = fourth_octet;
         event->RcvInvoke.tcl = tcl; 

         return event;
}

/*
 * We must swap the source and the destination address, because we are sending a
 * reply to a received message.
 */
static Address *deduce_reply_address(Msg *msg){

       Address *address = NULL;

       address = gw_malloc(sizeof(Address));
       address->source_address = 
                octstr_duplicate(msg->wdp_datagram.destination_address);
       address->source_port = msg->wdp_datagram.destination_port;
       address->destination_address = 
                octstr_duplicate(msg->wdp_datagram.source_address);
       address->destination_port = msg->wdp_datagram.source_port;

       return address;
}
