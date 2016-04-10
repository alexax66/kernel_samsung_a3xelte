#include <linux/cpufreq.h>
#include <linux/cpu.h>

extern bool screen_is_on;
extern unsigned int GLOBALKT_MIN_FREQ_LIMIT[];
extern unsigned int GLOBALKT_MAX_FREQ_LIMIT[];
extern unsigned int CPUINFO_MIN_FREQ_LIMIT[];
extern unsigned int CPUINFO_MAX_FREQ_LIMIT[];
extern unsigned int main_cpufreq_control[8];

//Main cpufreq.c vars
extern unsigned int vfreq_lock;

extern unsigned int is_charging;
extern bool call_in_progress;

//GPU
extern unsigned int gpu_max_override;
extern unsigned int cur_gpu_step;

extern bool ktoonservative_is_active;
extern unsigned int ktoonservative_hp_active;
extern void ktoonservative_boostpulse(bool boost_for_button);
extern void ktoonservative_screen_is_on(bool state, int cpu);
extern void cpufreq_screen_is_on(bool state);
