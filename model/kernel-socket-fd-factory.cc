#include "kernel-socket-fd-factory.h"
#include "kernel-socket-fd.h"
#include "loader-factory.h"
#include "dce-manager.h"
#include "process.h"
#include "utils.h"
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include "wait-queue.h"
#include "task-manager.h"
#include "kingsley-alloc.h"
#include "file-usage.h"
#include "dce-unistd.h"
#include "dce-stdlib.h"
#include "dce-semaphore.h"
#include "dce-pthread.h"
#include "sys/dce-stat.h"
#include "dce-fcntl.h"
#include "dce-stdio.h"
#include "dce_init.h"
#include "dce-host-ops.h"
#include "ns3/log.h"
#include "ns3/string.h"
#include "ns3/double.h"
#include "ns3/pointer.h"
#include "ns3/node.h"
#include "ns3/net-device.h"
#include "ns3/random-variable-stream.h"
#include "ns3/event-id.h"
#include "ns3/simulator.h"
#include "ns3/mac48-address.h"
#include "ns3/packet.h"
#include "exec-utils.h"
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#define LKL_FD_OFFSET (FD_SETSIZE/2)


NS_LOG_COMPONENT_DEFINE ("DceKernelSocketFdFactory");

extern struct lkl_host_operations lkl_host_ops;

namespace ns3 {

// Sadly NetDevice Callback add by method AddLinkChangeCallback take no parameters ..
// .. so we need to create the following class to link NetDevice and KernelSocketFdFactory together
// in order to do Warn the factory about which NetDevice is changing .
class KernelDeviceStateListener : public SimpleRefCount<KernelDeviceStateListener>
{
public:
  KernelDeviceStateListener (Ptr<NetDevice>, Ptr<KernelSocketFdFactory>);

  void NotifyDeviceStateChange ();

private:
  Ptr<NetDevice> m_netDevice;
  Ptr<KernelSocketFdFactory> m_factory;
};

KernelDeviceStateListener::KernelDeviceStateListener (Ptr<NetDevice> d,
                                                    Ptr<KernelSocketFdFactory> f)
  : m_netDevice (d),
    m_factory (f)
{
}

void
KernelDeviceStateListener::NotifyDeviceStateChange ()
{
  m_factory->NotifyDeviceStateChange (m_netDevice);
}

NS_OBJECT_ENSURE_REGISTERED (KernelSocketFdFactory);

TypeId
KernelSocketFdFactory::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::KernelSocketFdFactory")
    .SetParent<SocketFdFactory> ()
    .AddConstructor<KernelSocketFdFactory> ()
    .AddAttribute ("ErrorRate", "The error rate of malloc().",
                   DoubleValue (DoubleValue (0.0)),
                   MakeDoubleAccessor (&KernelSocketFdFactory::m_rate),
                   MakeDoubleChecker<double> ())
    .AddAttribute ("RanVar", "The decision variable attached to this error model.",
                   StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=1.0]"),
                   MakePointerAccessor (&KernelSocketFdFactory::m_ranvar),
                   MakePointerChecker<RandomVariableStream> ())
  ;
  return tid;
}
KernelSocketFdFactory::KernelSocketFdFactory ()
  : m_loader (0),
    m_kernelHandle (0),
    m_alloc (new KingsleyAlloc ()),
    m_logFile (0)
{
  TypeId::LookupByNameFailSafe ("ns3::LteUeNetDevice", &m_lteUeTid);
  m_variable = CreateObject<UniformRandomVariable> ();
}

KernelSocketFdFactory::~KernelSocketFdFactory ()
{
  for (uint32_t i = 0; i < m_devices.size (); i++)
    {
      // Note: we don't really destroy devices from here
      // because calling destroy requires a task context
      // m_kernelHandle->dev_destroy(m_devices[i].second);
    }
  delete m_kernelHandle;
  delete m_loader;
  delete m_alloc;
  if (m_logFile != 0)
    {
      fclose (m_logFile);
    }
  m_kernelHandle = 0;
  m_loader = 0;
  m_alloc = 0;
  m_logFile = 0;
}

void
KernelSocketFdFactory::DoDispose (void)
{
  for (std::list<Task *>::const_iterator i = m_kernelTasks.begin (); i != m_kernelTasks.end (); ++i)
    {
      m_manager->Stop (*i);
    }
  m_kernelTasks.clear ();
  m_manager = 0;
  m_listeners.clear ();
}


int
KernelSocketFdFactory::Vprintf (struct DceKernel *kernel, const char *str, va_list args)
{
  KernelSocketFdFactory *self = (KernelSocketFdFactory *)kernel;
  return vfprintf (self->m_logFile, str, args);
}

void *
KernelSocketFdFactory::Malloc (struct DceKernel *kernel, unsigned long size)
{
  KernelSocketFdFactory *self = (KernelSocketFdFactory *)kernel;
  if (self->m_ranvar->GetValue () < self->m_rate)
    {
      NS_LOG_DEBUG ("return null");
      // Inject fault
      return NULL;
    }

  size += sizeof (size_t);
  uint8_t *buffer = self->m_alloc->Malloc (size);
  memcpy (buffer, &size, sizeof (size_t));
  buffer += sizeof (size_t);
  return buffer;
}
void
KernelSocketFdFactory::Free (struct DceKernel *kernel, void *ptr)
{
  KernelSocketFdFactory *self = (KernelSocketFdFactory *)kernel;
  uint8_t *buffer = (uint8_t*)ptr;
  size_t size;
  buffer -= sizeof (size_t);
  memcpy (&size, buffer, sizeof (size_t));
  self->m_alloc->Free (buffer, size);
}
void *
KernelSocketFdFactory::Memcpy (struct DceKernel *kernel, void *dst, const void *src, unsigned long size)
{
  return memcpy (dst, src, size);
}
void *
KernelSocketFdFactory::Memset (struct DceKernel *kernel, void *dst, char value, unsigned long size)
{
  return memset (dst, value, size);
}
int
KernelSocketFdFactory::AtExit (struct DceKernel *kernel, void (*function)(void))
{
  NS_LOG_FUNCTION (kernel << function);
  KernelSocketFdFactory *self = (KernelSocketFdFactory *)kernel;
  Ptr<DceManager> manager = self->GetObject<DceManager> ();
  Process *p = manager->SearchProcess (self->m_pid);

  // Register process-level atexit store
  struct AtExitHandler handler;
  handler.type = AtExitHandler::NORMAL;
  handler.value.normal = function;
  p->atExitHandlers.push_back (handler);
  return 0;
}
int
KernelSocketFdFactory::Access (struct DceKernel *kernel, const char *pathname, int mode)
{
  return dce_access (pathname, mode);
}
char*
KernelSocketFdFactory::Getenv (struct DceKernel *kernel, const char *name)
{
  return dce_getenv (name);
}
int
KernelSocketFdFactory::Mkdir (struct DceKernel *kernel, const char *pathname, mode_t mode)
{
  return dce_mkdir (pathname, mode);
}
int
KernelSocketFdFactory::Open (struct DceKernel *kernel, const char *pathname, int flags)
{
  return dce_open (pathname, flags, 0666);
}
int
KernelSocketFdFactory::__Fxstat (struct DceKernel *kernel, int ver, int fd, void *buf)
{
  return dce___fxstat (ver, fd, (struct stat *)buf);
}
int
KernelSocketFdFactory::Fseek (struct DceKernel *kernel, FILE *stream, long offset, int whence)
{
  return dce_fseek (stream, offset, whence);
}
void
KernelSocketFdFactory::Setbuf (struct DceKernel *kernel, FILE *stream, char *buf)
{
  return dce_setbuf (stream, buf);
}
long
KernelSocketFdFactory::Ftell (struct DceKernel *kernel, FILE *stream)
{
  return dce_ftell (stream);
}
FILE*
KernelSocketFdFactory::FdOpen (struct DceKernel *kernel, int fd, const char *mode)
{
  return dce_fdopen (fd, mode);
}
size_t
KernelSocketFdFactory::Fread (struct DceKernel *kernel, void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  return dce_fread (ptr, size, nmemb, stream);
}
size_t
KernelSocketFdFactory::Fwrite (struct DceKernel *kernel, const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  return dce_fwrite (ptr, size, nmemb, stream);
}
int
KernelSocketFdFactory::Fclose (struct DceKernel *kernel, FILE *fp)
{
  return dce_fclose (fp);
}
unsigned long
KernelSocketFdFactory::Random (struct DceKernel *kernel)
{
  KernelSocketFdFactory *self = (KernelSocketFdFactory *)kernel;
  union
  {
    uint8_t buffer[sizeof(unsigned long)];
    unsigned long v;
  } u;
  for (uint8_t i = 0; i < sizeof (u.buffer); i++)
    {
      u.buffer[i] = self->m_variable->GetInteger (0,255);
    }
  return u.v;
}
void
KernelSocketFdFactory::Panic (struct DceKernel *kernel)
{
  KernelSocketFdFactory *self = (KernelSocketFdFactory *) kernel;
  Ptr<DceManager> manager = self->GetObject<DceManager> ();
  manager->Panic ();
}
void
KernelSocketFdFactory::EventTrampoline (void (*fn)(void *context),
                                       void *context, void (*pre_fn)(void),
                                       Ptr<EventIdHolder> event)
{
  m_loader->NotifyStartExecute ();
  pre_fn ();
  fn (context);
  m_loader->NotifyEndExecute ();
}
void *
KernelSocketFdFactory::EventScheduleNs (struct DceKernel *kernel, __u64 ns, void (*fn)(void *context), void *context,
                                       void (*pre_fn)(void))
{
  KernelSocketFdFactory *self = (KernelSocketFdFactory *)kernel;
  Ptr<EventIdHolder> ev = Create<EventIdHolder> ();
  TaskManager *manager = TaskManager::Current ();

  ev->id = manager->ScheduleMain (NanoSeconds (ns),
                                  MakeEvent (&KernelSocketFdFactory::EventTrampoline, self, fn, context, pre_fn, ev));

  return &ev->id;
}
void
KernelSocketFdFactory::EventCancel (struct DceKernel *kernel, void *ev)
{
  EventId *event = (EventId *)ev;
  Simulator::Remove (*event);
}
static __u64 CurrentNs (struct DceKernel *kernel)
{
  return Simulator::Now ().GetNanoSeconds ();
}

void
KernelSocketFdFactory::TaskSwitch (enum Task::SwitchType type, void *context)
{  
  NS_LOG_FUNCTION (type << context);
  Loader *loader = (Loader *)context;
  switch (type)
    {
    case Task::TO:
      loader->NotifyStartExecute ();
      break;
    case Task::FROM:
      loader->NotifyEndExecute ();
      break;
    }
}

struct SimTask *
KernelSocketFdFactory::TaskStart (struct DceKernel *kernel, void (*callback)(void *), void *context)
{  
  NS_LOG_FUNCTION (kernel << callback << context);  
  KernelSocketFdFactory *self = (KernelSocketFdFactory *)kernel;
  Task *task = self->m_manager->Start (callback, context, 1 << 17);
  struct SimTask *simTask = self->m_kernelHandle->task_create (task, 0);
  task->SetExtraContext (simTask);
  task->SetSwitchNotifier (&KernelSocketFdFactory::TaskSwitch, self->m_loader);
  self->m_kernelTasks.push_back (task);
  return (struct SimTask *)task->GetExtraContext ();
}
struct SimTask *
KernelSocketFdFactory::TaskCurrent (struct DceKernel *kernel)
{  
  NS_LOG_FUNCTION (kernel);  
  KernelSocketFdFactory *self = (KernelSocketFdFactory *)kernel;  
  TaskManager *manager = TaskManager::Current ();  
  Task *current = manager->CurrentTask ();  
  if (current->GetExtraContext () == 0)
    {
      uint32_t pid = 0;      
      struct Thread *thread = (struct Thread *)current->GetContext ();
      if (thread != 0)
        {
          pid = thread->process->pid;
        }      
      struct SimTask *simTask = self->m_kernelHandle->task_create (current, pid);      
      current->SetExtraContext (simTask);
    }  
  return (struct SimTask *)current->GetExtraContext ();
}

static void blank(void){

}

void
KernelSocketFdFactory::TaskWait (struct DceKernel *kernel , __u64 ns)
{
  NS_LOG_FUNCTION (kernel);
  // force initialization of 'current'
  //TaskCurrent (kernel);
  // now, sleep.
  //TaskManager::Current ()->Sleep (NanoSeconds(ns));
  //TaskManager::Current()->SleepOnly(NanoSeconds(ns));
  if(!NanoSeconds(ns).IsPositive()){
    //TaskSchedule();        
  }
  else{
    TaskManager::Current()->Sleep(NanoSeconds(ns));  
  }    
  //Simulator::Schedule (NanoSeconds(ns), &KernelSocketFdFactory::WakeupHack, kernel,TaskManager::Current()->CurrentTask()->GetExtraContext());

}

struct DceKernel * hack;

void
KernelSocketFdFactory::TaskSchedule(void)
{  
  NS_LOG_DEBUG("TaskSchedule");
  TaskManager::Current()->Sleep();
  //EventScheduleNs(hack,3000000000,TaskWakeup,TaskManager::Current()->CurrentTask(),blank);
  TaskManager::Current()->Schedule_Now();  
  NS_LOG_DEBUG("TaskSchedule Done");
}

void
KernelSocketFdFactory::WakeupHack(struct DceKernel *kernel, struct SimTask *task){
  TaskWakeup(kernel,task);
}

int
KernelSocketFdFactory::TaskWakeup (struct DceKernel *kernel, struct SimTask *task)
{  
  KernelSocketFdFactory *self = (KernelSocketFdFactory *)kernel;
  TaskManager *manager = TaskManager::Current ();
  if (!manager)
    {
      return 1;
    }
  Task *other = (Task *)self->m_kernelHandle->task_get_private (task);
  bool isBlocked = other->IsBlocked ();
  manager->Wakeup (other); 
  NS_LOG_DEBUG("WOkenUp") ;
  return isBlocked ? 1 : 0;
}
void
KernelSocketFdFactory::TaskYield (struct DceKernel *kernel)
{
  NS_LOG_FUNCTION (kernel);
  // force initialization of 'current'
  TaskCurrent (kernel);
  // now, yield.
  TaskManager::Current ()->Yield ();
}
void
KernelSocketFdFactory::SendMain (bool *r, NetDevice *dev, Ptr<Packet> p, const Address& d, uint16_t pro)
{
  *r = dev->Send (p, d, pro);
}
void
KernelSocketFdFactory::DevXmit (struct DceKernel *kernel, struct SimDevice *dev, unsigned char *data, int len)
{
  NS_LOG_FUNCTION (dev);
  KernelSocketFdFactory *self = (KernelSocketFdFactory *)kernel;
  NetDevice *nsDev = (NetDevice *)self->m_kernelHandle->dev_get_private (dev);
  NS_ASSERT (len >= 14);

  struct ethhdr
  {
    unsigned char   h_dest[6];
    unsigned char   h_source[6];
    uint16_t        h_proto;
  } *hdr = (struct ethhdr *)data;
  data += 14;
  len -= 14;
  Ptr<Packet> p = Create<Packet> (data, len);
  uint16_t protocol = ntohs (hdr->h_proto);
  Mac48Address dest;
  dest.CopyFrom (hdr->h_dest);
  TaskManager *manager = TaskManager::Current ();
  bool r = false;

  manager->ExecOnMain (MakeEvent (&KernelSocketFdFactory::SendMain, &r, nsDev, p, dest, protocol));
}

void
KernelSocketFdFactory::SignalRaised (struct DceKernel *kernel, struct SimTask *task, int signalNumber)
{
  NS_LOG_FUNCTION ("XXX: Not Yet Implemented " << signalNumber);
}

struct SimDevice *
KernelSocketFdFactory::DevToDev (Ptr<NetDevice> device)
{
  for (uint32_t i = 0; i < m_devices.size (); i++)
    {
      if (m_devices[i].first == device)
        {
          struct SimDevice *dev = m_devices[i].second;
          return dev;
        }
    }
  return 0;
}

void
KernelSocketFdFactory::RxFromDevice (Ptr<NetDevice> device, Ptr<const Packet> p,
                                    uint16_t protocol, const Address & from,
                                    const Address &to, NetDevice::PacketType type)
{
  struct SimDevice *dev = DevToDev (device);
  if (dev == 0)
    {
      return;
    }
  m_loader->NotifyStartExecute (); // Restore the memory of the kernel before access it !
  struct SimDevicePacket packet = m_kernelHandle->dev_create_packet (dev, p->GetSize () + 14);
  p->CopyData (((unsigned char *)packet.buffer) + 14, p->GetSize ());
  struct ethhdr
  {
    unsigned char   h_dest[6];
    unsigned char   h_source[6];
    uint16_t        h_proto;
  } *hdr = (struct ethhdr *)packet.buffer;
  if (device->GetInstanceTypeId () != m_lteUeTid)
    {
      Mac48Address realFrom = Mac48Address::ConvertFrom (from);
      realFrom.CopyTo (hdr->h_source);
    }
  Mac48Address realTo = Mac48Address::ConvertFrom (to);
  realTo.CopyTo (hdr->h_dest);
  hdr->h_proto = ntohs (protocol);
  m_kernelHandle->dev_rx (dev, packet);
  m_loader->NotifyEndExecute ();
}

void
KernelSocketFdFactory::NotifyDeviceStateChange (Ptr<NetDevice> device)
{
  ScheduleTask (MakeEvent (&KernelSocketFdFactory::NotifyDeviceStateChangeTask,
                           this, device));
}
void
KernelSocketFdFactory::NotifyDeviceStateChangeTask (Ptr<NetDevice> device)
{  
  NS_LOG_FUNCTION (device);
  struct SimDevice *dev = DevToDev (device);
  if (dev == 0)
    {
      return;
    }
  Mac48Address ad = Mac48Address::ConvertFrom (device->GetAddress ());
  uint8_t buffer[6];
  ad.CopyTo (buffer);
  m_loader->NotifyStartExecute (); // Restore the memory of the kernel before access it !
  m_kernelHandle->dev_set_address (dev, buffer);
  m_kernelHandle->dev_set_mtu (dev, device->GetMtu ());
  m_loader->NotifyEndExecute ();
}

void
KernelSocketFdFactory::ScheduleTaskTrampoline (void *context)
{
  NS_LOG_FUNCTION(context);
  Task *current = TaskManager::Current ()->CurrentTask ();
  KernelSocketFdFactory *self = (KernelSocketFdFactory *) current->GetExtraContext ();
  current->SetExtraContext (0);
  EventImpl *event = (EventImpl *)context;
  event->Invoke ();
  event->Unref ();
  self->m_kernelTasks.remove (current);
  TaskManager::Current ()->Exit ();
}

void
KernelSocketFdFactory::ScheduleTask (EventImpl *event)
{
  Task *task = m_manager->Start (&KernelSocketFdFactory::ScheduleTaskTrampoline,
                                 event, 1 << 17);
  task->SetExtraContext (this);
  task->SetSwitchNotifier (&KernelSocketFdFactory::TaskSwitch, m_loader);
  m_kernelTasks.push_back (task);  
}

void
KernelSocketFdFactory::NotifyAddDevice (Ptr<NetDevice> device)
{
  ScheduleTask (MakeEvent (&KernelSocketFdFactory::NotifyAddDeviceTask, this, device));
}
void
KernelSocketFdFactory::NotifyAddDeviceTask (Ptr<NetDevice> device)
{
  NS_LOG_FUNCTION (device);
  int flags = 0;
  //NS_ASSERT (!device->IsPointToPoint ());
  //NS_ASSERT (device->NeedsArp ());
  //NS_ASSERT (device->IsMulticast ());
  //NS_ASSERT (device->IsBroadcast ());
  if (device->IsMulticast ())
    {
      flags |= SIM_DEV_MULTICAST;
    }
  if (device->IsBroadcast ())
    {
      flags |= SIM_DEV_BROADCAST;
    }
  if (!device->NeedsArp ())
    {
      flags |= SIM_DEV_NOARP;
    }
  NS_LOG_INFO("Checks Done");
  m_loader->NotifyStartExecute (); // Restore the memory of the kernel before access it !
  NS_LOG_INFO("NotifyStartExecute Finished");  
  struct SimDevice *dev = m_kernelHandle->dev_create ("sim%d", PeekPointer (device), (enum SimDevFlags)flags);
  NS_LOG_INFO("dev_create Finished");
  m_loader->NotifyEndExecute ();
  NS_LOG_INFO("NotifyEndExecute Finished");
  Ptr<KernelDeviceStateListener> listener = Create <KernelDeviceStateListener> (device, this);
  m_listeners.push_back (listener);
  device->AddLinkChangeCallback (MakeCallback (&KernelDeviceStateListener::NotifyDeviceStateChange, listener));

  m_devices.push_back (std::make_pair (device,dev));
  Ptr<Node> node = GetObject<Node> ();
  if (device->GetInstanceTypeId () == m_lteUeTid)
    {
      node->RegisterProtocolHandler (MakeCallback (&KernelSocketFdFactory::RxFromDevice, this),
                                     0, device, false);
    }
  else
    {
      node->RegisterProtocolHandler (MakeCallback (&KernelSocketFdFactory::RxFromDevice, this),
                                     0, device, true);
    }
  NotifyDeviceStateChangeTask (device);
}

bool added = false;


static int parse_mac_str(char *mac_str, __lkl__u8 mac[LKL_ETH_ALEN])
{
	char delim[] = ":";
	char *saveptr = NULL, *token = NULL;
	int i = 0;

	if (!mac_str)
		return 0;

	for (token = strtok_r(mac_str, delim, &saveptr);
	     i < LKL_ETH_ALEN; i++) {
		if (!token) {
			/* The address is too short */
			return -1;
		}

		mac[i] = (__lkl__u8) strtol(token, NULL, 16);
		token = strtok_r(NULL, delim, &saveptr);
	}

	if (strtok_r(NULL, delim, &saveptr)) {
		/* The address is too long */
		return -1;
	}

	return 1;
}

static void PinToCpus(const cpu_set_t* cpus)
{
	if (sched_setaffinity(0, sizeof(cpu_set_t), cpus)) {
		perror("sched_setaffinity");
	}
}

static void PinToFirstCpu(const cpu_set_t* cpus)
{
	int j;
	cpu_set_t pinto;
	CPU_ZERO(&pinto);
	for (j = 0; j < CPU_SETSIZE; j++) {
		if (CPU_ISSET(j, cpus)) {			
			CPU_SET(j, &pinto);
			PinToCpus(&pinto);
			return;
		}
	}
}
static struct lkl_netdev *nd;
struct lkl_netdev_args nd_args;

int lkl_call(int nr, int args, ...)
{
	long params[6];
	va_list vl;
	int i;

	va_start(vl, args);
	for (i = 0; i < args; i++)
		params[i] = va_arg(vl, long);
	va_end(vl);
  return (*fx_lkl_syscall)(nr,params);	
}


void
KernelSocketFdFactory::InitializeStack (void)
{
  std::string filePath = SearchExecFile ("DCE_PATH", m_library, 0);
  if (filePath.length () <= 0)
    {
      std::string line = "Stack file '";
      line += m_library;
      line += "' not found ! Please check your DCE_PATH environment variable.";
      NS_ASSERT_MSG (filePath.length () > 0, line.c_str ());
      return ;
    }
  
  void *handle = m_loader->Load (filePath, RTLD_LOCAL);

  // Setup LKL Kernel

 
  void *symbol = m_loader->Lookup (handle, "sim_init");
  SimInit init = (SimInit) symbol;
  if (init == 0)
    {
      NS_FATAL_ERROR ("Oops. Can't find initialization function");
    }
  m_kernelHandle = new struct KernelHandle ();
  struct DceHandle dceHandle;
  dceHandle.vprintf = &KernelSocketFdFactory::Vprintf;
  dceHandle.malloc = &KernelSocketFdFactory::Malloc;
  dceHandle.free = &KernelSocketFdFactory::Free;
  dceHandle.memcpy = &KernelSocketFdFactory::Memcpy;
  dceHandle.memset = &KernelSocketFdFactory::Memset;
  dceHandle.atexit = &KernelSocketFdFactory::AtExit;
  dceHandle.panic = &KernelSocketFdFactory::Panic;
  dceHandle.access = &KernelSocketFdFactory::Access;
  dceHandle.getenv = &KernelSocketFdFactory::Getenv;
  dceHandle.mkdir = &KernelSocketFdFactory::Mkdir;
  dceHandle.open = &KernelSocketFdFactory::Open;
  dceHandle.__fxstat = &KernelSocketFdFactory::__Fxstat;
  dceHandle.fseek = &KernelSocketFdFactory::Fseek;
  dceHandle.setbuf = &KernelSocketFdFactory::Setbuf;
  dceHandle.ftell = &KernelSocketFdFactory::Ftell;
  dceHandle.fdopen = &KernelSocketFdFactory::FdOpen;
  dceHandle.fread = &KernelSocketFdFactory::Fread;
  dceHandle.fwrite = &KernelSocketFdFactory::Fwrite;
  dceHandle.fclose = &KernelSocketFdFactory::Fclose;
  dceHandle.random = &KernelSocketFdFactory::Random;
  dceHandle.event_schedule_ns = &KernelSocketFdFactory::EventScheduleNs;
  dceHandle.event_cancel = &KernelSocketFdFactory::EventCancel;
  dceHandle.current_ns = &CurrentNs;
  dceHandle.task_start = &KernelSocketFdFactory::TaskStart;
  dceHandle.task_wait = &KernelSocketFdFactory::TaskWait;
  dceHandle.task_schedule = &KernelSocketFdFactory::TaskSchedule;
  dceHandle.task_current = &KernelSocketFdFactory::TaskCurrent;
  dceHandle.task_wakeup = &KernelSocketFdFactory::TaskWakeup;
  dceHandle.task_yield = &KernelSocketFdFactory::TaskYield;
  dceHandle.dev_xmit = &KernelSocketFdFactory::DevXmit;
  dceHandle.signal_raised = &KernelSocketFdFactory::SignalRaised;
  dceHandle.poll_event = &KernelSocketFdFactory::PollEvent;
  // create internal process  
  Ptr<DceManager> manager = this->GetObject<DceManager> ();  

  m_pid = manager->StartInternalTask ();  

  fx_lkl_start_kernel =  m_loader->Lookup(handle, "lkl_start_kernel");  
  fx_lkl_netdev_tap_create = m_loader->Lookup(handle, "lkl_netdev_tap_create");  
  fx_lkl_netdev_add = m_loader->Lookup(handle, "lkl_netdev_add");  
  lib_lkl_host_ops = m_loader->Lookup(handle,"lkl_host_ops");

  fx_lkl_set_fd_limit = m_loader->Lookup(handle,"lkl_set_fd_limit");
  fx_lkl_sys_mknod = m_loader->Lookup(handle,"lkl_sys_mknod");
  fx_lkl_sys_open = m_loader->Lookup(handle,"lkl_sys_open");
  fx_lkl_sys_dup = m_loader->Lookup(handle,"lkl_sys_dup");
  fx_lkl_if_up = m_loader->Lookup(handle,"lkl_if_up");

  fx_lkl_syscall = m_loader->Lookup(handle,"lkl_syscall");

  fx_lkl_ioremap = m_loader->Lookup(handle, "lkl_ioremap");
  fx_lkl_iomem_access = m_loader->Lookup(handle, "lkl_iomem_access");
  fx_jmp_buf_set = m_loader->Lookup(handle, "jmp_buf_set");
  fx_jmp_buf_longjmp = m_loader->Lookup(handle, "jmp_buf_longjmp");
  char_lkl_virtio_devs = m_loader->Lookup(handle, "lkl_virtio_devs");

  lkl_host_ops.ioremap = fx_lkl_ioremap;
  lkl_host_ops.iomem_access = fx_lkl_iomem_access;
  lkl_host_ops.jmp_buf_set = fx_jmp_buf_set;
  lkl_host_ops.jmp_buf_longjmp = fx_jmp_buf_longjmp;
  lkl_host_ops.virtio_devices = char_lkl_virtio_devs; 

  *lib_lkl_host_ops = lkl_host_ops;
  hack = (struct DceKernel *)this;
  init (m_kernelHandle, &dceHandle, (struct DceKernel *)this); 


if(!added){
  
  __lkl__u8 mac[LKL_ETH_ALEN] = {0};
  memset(&nd_args, 0, sizeof(struct lkl_netdev_args));
  int offload = strtol("0xc803", NULL, 0);

  nd = (*fx_lkl_netdev_tap_create)("tap",offload);  
  

  char mac_addr[] = "12:34:56:78:9a:bc";
  parse_mac_str(mac_addr, mac);
    
  nd_args.mac = mac;
  nd_args.offload = offload;


  int ret = (*fx_lkl_netdev_add)(nd,&nd_args);
  

  nd->id = ret;
  added = true;
  }
  

  cpu_set_t ori_cpu;  
	
	PinToFirstCpu(&ori_cpu);
  
  (*fx_lkl_start_kernel)(&lkl_host_ops,"");
  
  
  int ret = (*fx_lkl_set_fd_limit)(65535);	  
	
	ret = lkl_call(__lkl__NR_mknodat,4,LKL_AT_FDCWD,"/dev_null", LKL_S_IFCHR | 0600, LKL_MKDEV(1, 3));  
  
	int dev_null = lkl_call(__lkl__NR_openat,4,LKL_AT_FDCWD,"/dev_null", LKL_O_RDONLY, 0);
	if (dev_null < 0) {
		NS_FATAL_ERROR("Failed to open /dev/null");
		return;
	}

	for (int i = 1; i < LKL_FD_OFFSET; i++)
		lkl_call(__lkl__NR_dup,1,dev_null);  
	
	(*fx_lkl_if_up)(1);  


  // update the kernel device list with simulation device list
  Ptr<Node> node = GetObject<Node> ();
  node->RegisterDeviceAdditionListener (MakeCallback (&KernelSocketFdFactory::NotifyAddDevice,
                                                      this));

  NS_LOG_FUNCTION (this << "m_kernelHandle " << m_kernelHandle);
}

UnixFd *
KernelSocketFdFactory::CreateSocket (int domain, int type, int protocol)
{
  GET_CURRENT (this << domain << type << protocol);
  struct DceSocket *socket;
  m_loader->NotifyStartExecute ();
  
  int retval = m_kernelHandle->sock_socket (domain, type, protocol, &socket);  
  //socket = lkl_call(__lkl__NR_socket,3,domain,type,protocol);  
  
  m_loader->NotifyEndExecute ();
  if (retval < 0)
    {      
      NS_FATAL_ERROR("No Socket created");
      return 0;
    }
  UnixFd *fd = new KernelSocketFd (this, socket);

  return fd;
}

int
KernelSocketFdFactory::Close (struct DceSocket *socket)
{
  GET_CURRENT (socket);
  m_loader->NotifyStartExecute ();
  int retval = m_kernelHandle->sock_close (socket);
  //int retval = lkl_call(__lkl__NR_close,1,socket);
  m_loader->NotifyEndExecute ();
  if (retval < 0)
    {
      NS_FATAL_ERROR("Close");
      current->err = -retval;
      return -1;
    }
  return retval;
}
ssize_t
KernelSocketFdFactory::Recvmsg (struct DceSocket *socket, struct msghdr *msg, int flags)
{
  GET_CURRENT (socket << msg << flags);
  m_loader->NotifyStartExecute ();
  ssize_t retval = m_kernelHandle->sock_recvmsg (socket, msg, flags);
  //int retval = lkl_call(__lkl__NR_recvmsg,3,socket,msg,flags);
  m_loader->NotifyEndExecute ();
  if (retval < 0)
    {
      NS_FATAL_ERROR("RcvMsg");
      current->err = -retval;
      return -1;
    }
  return retval;
}
ssize_t
KernelSocketFdFactory::Sendmsg (struct DceSocket *socket, const struct msghdr *msg, int flags)
{
  GET_CURRENT (socket << msg << flags);
  m_loader->NotifyStartExecute ();
  ssize_t retval = m_kernelHandle->sock_sendmsg (socket, msg, flags);
  //int retval = lkl_call(__lkl__NR_sendmsg,3,socket,msg,flags);
  m_loader->NotifyEndExecute ();
  if (retval < 0)
    {
      NS_FATAL_ERROR("SendMsg");
      current->err = -retval;
      return -1;
    }
  return retval;
}
int
KernelSocketFdFactory::Getsockname (struct DceSocket *socket, struct sockaddr *name, socklen_t *namelen)
{
  GET_CURRENT (socket << name << namelen);
  m_loader->NotifyStartExecute ();
  int retval = m_kernelHandle->sock_getsockname (socket, name, (int*)namelen);
  //int retval = lkl_call(__lkl__NR_getsockname,3,socket,name,namelen);
  m_loader->NotifyEndExecute ();
  if (retval < 0)
    {
      NS_FATAL_ERROR("getsockname");
      NS_FATAL_ERROR(retval);
      current->err = -retval;      
      return -1;
    }
  return retval;
}
int
KernelSocketFdFactory::Getpeername (struct DceSocket *socket, struct sockaddr *name, socklen_t *namelen)
{
  GET_CURRENT (socket << name << namelen);
  m_loader->NotifyStartExecute ();
  int retval = m_kernelHandle->sock_getpeername (socket, name, (int*)namelen);
  //int retval = lkl_call(__lkl__NR_getpeername,3,socket,name,namelen);
  
  m_loader->NotifyEndExecute ();
  if (retval < 0)
    {
      NS_FATAL_ERROR("getpeername");
      current->err = -retval;
      return -1;
    }
  return retval;
}
int
KernelSocketFdFactory::Bind (struct DceSocket *socket, const struct sockaddr *my_addr, socklen_t addrlen)
{
  GET_CURRENT (socket << my_addr << addrlen);
  m_loader->NotifyStartExecute ();
  int retval = m_kernelHandle->sock_bind (socket, my_addr, addrlen);
  //int retval = lkl_call(__lkl__NR_bind,3,socket,my_addr,addrlen);
  m_loader->NotifyEndExecute ();
  if (retval < 0)
    {
      NS_FATAL_ERROR("bind");
      current->err = -retval;
      return -1;
    }
  return retval;
}
int
KernelSocketFdFactory::Connect (struct DceSocket *socket, const struct sockaddr *my_addr,
                               socklen_t addrlen, int flags)
{
  GET_CURRENT (socket << my_addr << addrlen << flags);
  m_loader->NotifyStartExecute ();
  int retval = m_kernelHandle->sock_connect (socket, my_addr, addrlen, flags);
  //int retval = lkl_call(__lkl__NR_connect,4,socket,my_addr,addrlen,flags);
  m_loader->NotifyEndExecute ();
  if (retval < 0)
    {
      NS_FATAL_ERROR("connect");
      current->err = -retval;
      return -1;
    }
  return retval;
}
int
KernelSocketFdFactory::Listen (struct DceSocket *socket, int backlog)
{
  GET_CURRENT (socket << backlog);
  m_loader->NotifyStartExecute ();
  int retval = m_kernelHandle->sock_listen (socket, backlog);
  //int retval = lkl_call(__lkl__NR_listen,2,socket,backlog);
  m_loader->NotifyEndExecute ();
  if (retval < 0)
    {
      NS_FATAL_ERROR("listen");
      current->err = -retval;
      return -1;
    }
  return retval;
}
int
KernelSocketFdFactory::Shutdown (struct DceSocket *socket, int how)
{
  GET_CURRENT (socket << how);
  m_loader->NotifyStartExecute ();
  int retval = m_kernelHandle->sock_shutdown (socket, how);
  //int retval = lkl_call(__lkl__NR_shutdown,2,socket,how);
  m_loader->NotifyEndExecute ();
  if (retval < 0)
    {
      NS_FATAL_ERROR("shutdown");
      current->err = -retval;
      return -1;
    }
  return retval;
}
int
KernelSocketFdFactory::Accept (struct DceSocket *socket, struct sockaddr *my_addr, socklen_t *addrlen, int flags)
{
  GET_CURRENT (socket << my_addr << addrlen << flags);
  struct DceSocket *newSocket;
  m_loader->NotifyStartExecute ();
  
  int retval = m_kernelHandle->sock_accept (socket, &newSocket, my_addr, addrlen, flags);  
    
  //int retval = lkl_call(__lkl__NR_accept,4,socket,my_addr,addrlen,flags);
  m_loader->NotifyEndExecute ();
  /*
  if (retval < 0)
    {
      current->err = -retval;
      return -1;
    }
  if (my_addr != 0)
    {
      m_loader->NotifyStartExecute ();
      retval = m_kernelHandle->sock_getpeername (newSocket, my_addr, (int*)addrlen);
      //retval = lkl_call(__lkl__NR_getpeername,3,newSocket,my_addr,addrlen);
      if (retval < 0)
        {
          current->err = -retval;
          m_kernelHandle->sock_close (newSocket);
          //lkl_call(__lkl__NR_close,1,newSocket);
          m_loader->NotifyEndExecute ();
          return -1;
        }
      m_loader->NotifyEndExecute ();
    }*/
  int fd = UtilsAllocateFd ();
  if (fd == -1)
    {
      m_loader->NotifyStartExecute ();
      m_kernelHandle->sock_close (newSocket);
      //lkl_call(__lkl__NR_close,1,newSocket);
      current->err = EMFILE;
      m_loader->NotifyEndExecute ();
      return -1;
    }
  UnixFd *unixFd = new KernelSocketFd (this, newSocket);
  unixFd->IncFdCount ();
  current->process->openFiles[fd] = new FileUsage (fd, unixFd);

  return fd;
}
int
KernelSocketFdFactory::Ioctl (struct DceSocket *socket, unsigned long request, char *argp)
{
  GET_CURRENT (socket << request << argp);
  m_loader->NotifyStartExecute ();
  int retval = m_kernelHandle->sock_ioctl (socket, request, argp);
  //int retval = lkl_call(__lkl__NR_ioctl,3,socket,request,argp);
  m_loader->NotifyEndExecute ();
  if (retval < 0)
    {      
      current->err = -retval;
      return -1;
    }
  return retval;
}
int
KernelSocketFdFactory::Setsockopt (struct DceSocket *socket, int level, int optname,
                                  const void *optval, socklen_t optlen)
{
  GET_CURRENT (socket << level << optname << optval << optlen);
  m_loader->NotifyStartExecute ();
  int retval = m_kernelHandle->sock_setsockopt (socket, level, optname, optval, optlen);
  
  //int retval = lkl_call(__lkl__NR_setsockopt,5,socket,level,optname,optval,optlen);  
  m_loader->NotifyEndExecute ();
  if (retval < 0)
    {
      current->err = -retval;
      return -1;
    }
  return retval;
}
int
KernelSocketFdFactory::Getsockopt (struct DceSocket *socket, int level, int optname,
                                  void *optval, socklen_t *optlen)
{
  GET_CURRENT (socket << level << optname << optval << optlen);
  m_loader->NotifyStartExecute ();
  int retval = m_kernelHandle->sock_getsockopt (socket, level, optname, optval, (int*)optlen);
  //int retval = lkl_call(__lkl__NR_getsockopt,5,socket,level,optname,optval,optlen);
  m_loader->NotifyEndExecute ();
  if (retval < 0)
    {
      current->err = -retval;
      return -1;
    }
  return retval;
}
void
KernelSocketFdFactory::PollEvent (int flag, void *context)
{
  PollTable* ptable = (PollTable*)context;
  ptable->WakeUpCallback ();
}

/**
 * Struct used to pass pool table context between DCE and Kernel and back from Kernel to DCE
 *
 * When calling sock_poll we provide in ret field the wanted eventmask, and in the opaque field
 * the DCE poll table
 *
 * if a corresponding event occurs later, the PollEvent will be called by kernel with the DCE
 * poll table in context variable, then we will able to wake up the thread blocked in poll call.
 *
 * Back from sock_poll method the kernel change ret field with the response from poll return of the
 * corresponding kernel socket, and in opaque field there is a reference to the kernel poll table
 * we will use this reference to remove us from the file wait queue when ending the DCE poll call or
 * when ending the DCE process which is currently polling.
 *
 */
struct poll_table_ref
{
  int ret;
  void *opaque;
};
int
KernelSocketFdFactory::Poll (struct DceSocket *socket, PollTable* ptable)
{
  struct poll_table_ref kernelInOut =
  {
    0
  };
  if (ptable)
    {
      // Fill Opaque and ptable.
      kernelInOut.opaque = ptable;
      kernelInOut.ret = ptable->GetEventMask ();
    }

  GET_CURRENT (socket);
  m_loader->NotifyStartExecute ();
  m_kernelHandle->sock_poll (socket, &kernelInOut);
  m_loader->NotifyEndExecute ();

  if (ptable)
    {
      ptable->PollWait (kernelInOut.opaque, MakeCallback (&KernelSocketFdFactory::PollFreeWait, this));
    }

  return kernelInOut.ret;
}
void
KernelSocketFdFactory::PollFreeWait (void *ref)
{
  m_loader->NotifyStartExecute ();
  m_kernelHandle->sock_pollfreewait (ref);
  m_loader->NotifyEndExecute ();
}
} // namespace ns3
