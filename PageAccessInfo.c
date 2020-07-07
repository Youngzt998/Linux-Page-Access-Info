/*
    SJTU-CS353 
    Linux Kernal Project
*/

/*
    Student Name: Ziteng Yang
    StudentID: 517021910683
*/

/*
    
*/
#include<linux/string.h>


#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include <linux/moduleparam.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>

#include <linux/slab.h>

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/highmem.h>




//#include <stdlib.h>
MODULE_LICENSE("Dual BSD/GPL");

#define MAX_PID 32767
#define MAX_INFO_NUM 1000000


pte_t* get_pte_by_vm(struct task_struct* task, unsigned long addr)
{
    pgd_t* pgd; 
    p4d_t* p4d; 
    pud_t* pud; 
    pmd_t* pmd; 
    pte_t* pte;

    pgd = pgd_offset(task->mm, addr);
    if(pgd_none(*pgd))
    {
        return 1;
    }

    p4d = p4d_offset(pgd, addr);
    if(p4d_none(*p4d))
    {
        return 1;
    }

    pud = pud_offset(p4d, addr);
    if(pud_none(*pud))
    {
        return 1;
    }

    pmd = pmd_offset(pud, addr);
    if(pmd_none(*pmd))
    {
        return 1;
    }

    pte = pte_offset_kernel(pmd, addr);
    if(pte_none(*pte))
    {
        return 2;
    }

    return pte;
} 


struct page_info{
    unsigned long phy_addr;
    unsigned long access_num; 
};

struct page_info* info;
struct pid* cur_pid; 
unsigned long count[10];

/* 
    Print all vma of the current process 
*/  
static unsigned long collect_info(struct task_struct* task)
{
    struct vm_area_struct* p;   //line 292 in mm_type.h
    struct mm_struct *mm;
    pte_t* src_pte;
    pte_t pte;
    unsigned long pte_min = 2140483647, pte_max = 0;
    unsigned long page_size = (~ PAGE_MASK) +1;
    unsigned long i, phy_addr;
    unsigned long heap_counter = 0, heap_young_counter = 0;
    unsigned long pte_counter = 0;
    bool isheap = true;
    // char tmp[PATH_MAX];
    char* name;
    if(!task){
        printk("task is null!\n");
        return 1;
    }

    printk(KERN_INFO"Virtual memory area:\n");
    down_write(&task->mm->mmap_sem);
        for(p = task->mm->mmap; p!=NULL; p=p->vm_next)
        {
            mm = p->vm_mm;
            printk(
                KERN_INFO"0x%08lx - 0x%08lx\t0x%08lx \n", 
                p->vm_start, p->vm_end,
                p->vm_end - p->vm_start
            );

            // name = arch_vma_name(p);
            name = NULL;
            if (!name) {
                if (!mm) {
                    name = "[vdso]";
                    isheap = false;
                    continue;
                }

                if (p->vm_start <= task->mm->brk &&
                    p->vm_end >= task->mm->start_brk) {
                    name = "[heap]";
                    isheap = true;
                    printk("%s", name);
                }
                else {
                    isheap = false;
                    continue;
                }
            }
            else
            {
                continue;
            }

            // pte_counter += (p->vm_end - p->vm_start) >> PAGE_SHIFT;
            printk("Start - End: 0x%08lx - 0x%08lx\n", p->vm_start, p->vm_end);
            for(i=p->vm_start; i<p->vm_end;i+=page_size){
                src_pte = get_pte_by_vm(task, i);
                if(src_pte == 1 || src_pte == 2)
                {
                    continue;
                }

                if(src_pte < pte_min){
                    pte_min = src_pte;
                }
                
                if(src_pte > pte_max){
                    pte_max = src_pte;
                }

                phy_addr = pte_val(*src_pte) & PAGE_MASK;
                // printk("pte: 0x%08lx\t", src_pte);
                // printk("\tPhysical page in heap: 0x%08lx\t%s\n", 
                //     phy_addr, pte_young(*src_pte)? "young":"old");
                heap_counter ++;
                if(pte_young(*src_pte)){
                    heap_young_counter ++;
                    // printk("\tPhysical page (young): 0x%08lx\n", phy_addr);
                    // *src_pte = pte_mkold(*src_pte);
                    if(info[pte_counter].phy_addr==0 && 
                        phy_addr != 0){
                        info[pte_counter].phy_addr = phy_addr;
                    }
                    else if(info[pte_counter].phy_addr!=0 && 
                        info[pte_counter].phy_addr != phy_addr){
                        printk("phy_addr not consistent!\n");
                    }
                    info[pte_counter].access_num += 1;
                    *src_pte = pte_mkold(*src_pte);
                    // pte = pte_mkold(*src_pte);
                    // set_pte_at(task->mm, i, src_pte, pte);
                }
                pte_counter += 1;
                if (pte_counter == MAX_INFO_NUM)
                {
                    printk("Too many pages, exit!\n");
                    return 0;
                }
                
            }

        }
    up_write(&task->mm->mmap_sem);
    printk("PAGE_SHIFT = %d\n", PAGE_SHIFT);
    printk("Page size: 0x%08lx\n", page_size);
    printk("Total pages in heap:\t%ld\n", pte_counter);
    printk("Physical pages in heap:\t%ld\n", heap_counter);
    printk("Physical pages in heap (young):\t%ld\n", heap_young_counter);
    printk("pte_max: 0x%08lx\n", pte_max);
    printk("pte_min: 0x%08lx\n", pte_min);
    printk("interval: 0x%08lx\n", pte_max - pte_min);

    return heap_counter;
} 


/*******************************************************************/

static char* output = "YZT's";

/*
    Using cat /proc/*filename to open the (virtual) file   
*/
static int proc_show(struct seq_file *m, void *v) {
    unsigned long i;
    unsigned long counter;
    seq_printf(m, "Page info: %s\n", output);
    if(!info){
        seq_printf(m, "No accessible information\n");
    }
    for(i = 0; i< MAX_INFO_NUM; ++i){
        // printk("info_num: %d\n", i);
        if(info[i].access_num >= 0 && info[i].access_num <= 5){
            count[info[i].access_num] += 1;

        }
        // seq_printf(m, "Physical address: 0x%08lx\tAccesed time:%d\n", 
        //     info[i].phy_addr, info[i].access_num);
    }
    for (i = 0; i<=5; ++i){
        seq_printf(m, "%d pages was accessed %d times\n", count[i], i);
    }

    return 0;
}

static int proc_open(struct inode *inode, struct file *file) {
    return single_open(file, proc_show, NULL);
}


static ssize_t proc_write(struct file *file, const char __user *buffer, 
                            size_t count, loff_t *f_pos) 
{
    int i = -1;
    char* content = kzalloc((count+1), GFP_KERNEL);
    unsigned long pid;
    struct pid* current_pid;
    static struct task_struct *current_task;

    if(!content) return -ENOMEM;
    if(copy_from_user(content, buffer, count)){
        kfree(content);
        return EFAULT;
    }



    if (kstrtol(content, 10, &pid) != 0)
    {
        printk("Error translating address to int!\n");
    }
    else
    {
        // printk("pid: %d\n", pid);
    }

    if(pid == 0){   //clear info
        printk("clear info\n");
        for(i = 0; i< MAX_INFO_NUM; ++i){
            // printk("info_num: %d\n", i);
            info[i].phy_addr = 0;
            info[i].access_num = 0;
        }
        return 0;
    }
    
    
    current_pid=find_get_pid(pid);
    current_task=get_pid_task(current_pid,PIDTYPE_PID);
    if(!current_task)
    {
        printk("error finding task_struct!\n");
        return 2;
    }
    printk(KERN_INFO"pid: %d\tname: %s\n", current_task->pid, current_task->comm);
    

    collect_info(current_task);

    return 0;
}


static const struct file_operations mkfile_fops = {
    // .owner= THIS_MODULE,
    .open = proc_open,          // the function called after opening operation
    .read = seq_read,
    .write = proc_write,        // the function called after writing operation
    // .llseek = seq_lseek,
    // .release = single_release
};


static char* file_name = "PageAccessInfo";
struct proc_dir_entry *my_dir;
struct proc_dir_entry *my_file;

static int __init init_fun(void)
{
    int i;
    printk(KERN_INFO "PageAccessInfo: module load!\n");
    
    /*
        create the "directory" with name dir_name
    */
    // my_dir = proc_mkdir(dir_name, NULL);
    my_dir = NULL;

    /*
        create the "file" with name file_name
        0x666 means writable
    */
    my_file = proc_create(file_name, 0x0666, my_dir, &mkfile_fops);
    
    printk("before vmalloc\n");
    printk("MAX_INFO_NUM: 0x%08lx\n", MAX_INFO_NUM);
    printk("sizeof pageinfo: %d\n", sizeof(struct page_info));
    info = (struct page_info*) vmalloc(MAX_INFO_NUM * sizeof(struct page_info));
    if(!info){
        printk("vmalloc error!\n");
        return 0;
    }
    printk("info: 0x%08lx\n", info);
    for(i = 0; i< MAX_INFO_NUM; ++i){
        // printk("info_num: %d\n", i);
        info[i].phy_addr = 0;
        info[i].access_num = 0;
    }
    return 0;
}

static void __exit exit_fun(void)
{

    remove_proc_entry(file_name, my_dir);
    //remove_proc_entry(dir_name, NULL);


    // kfree(content);
    printk(KERN_INFO "PageAccessInfo: module exit!\n"); 

}


module_init(init_fun);
module_exit(exit_fun);
