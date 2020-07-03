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


pte_t* get_pte_by_vm(unsigned long addr)
{
    pgd_t* pgd; 
    p4d_t* p4d; 
    pud_t* pud; 
    pmd_t* pmd; 
    pte_t* pte;

    pgd = pgd_offset(current->mm, addr);
    if(pgd_none(*pgd))
    {
        return -1;
    }

    p4d = p4d_offset(pgd, addr);
    if(p4d_none(*p4d))
    {
        return -1;
    }

    pud = pud_offset(p4d, addr);
    if(pud_none(*pud))
    {
        return -1;
    }

    pmd = pmd_offset(pud, addr);
    if(pmd_none(*pmd))
    {
        return-1;
    }

    pte = pte_offset_kernel(pmd, addr);
    if(pte_none(*pte))
    {
        return-1;
    }

    return pte;
} 


/* 
    Print all vma of the current process 
*/  
static void list_vma(void)
{
    struct vm_area_struct* p;   //line 292 in mm_type.h
    pte_t* pte;
    unsigned long page_size = (~ PAGE_MASK) +1;
    unsigned long i, phy_addr;


    printk("PAGE_SHIFT = %d\n", PAGE_SHIFT);
    printk("Page size: 0x%08lx\n", page_size);
    printk(KERN_INFO"Virtual memory area:\n");
    down_write(&current->mm->mmap_sem);
        for(p = current->mm->mmap; p!=NULL; p=p->vm_next)
        {
            printk(
                KERN_INFO"0x%08lx - 0x%08lx\t0x%08lx \n", 
                p->vm_start, p->vm_end,
                p->vm_end - p->vm_start
            );
            for(i=p->vm_start; i<p->vm_end;i+=page_size){
                pte = get_pte_by_vm(i);
                if(pte == -1)
                {
                    // printk("\tWrong address\n");
                    continue;
                }
                phy_addr = pte_val(*pte) & PAGE_MASK;
                printk("\tPhysical address: 0x%08lx\t%s\n", 
                    phy_addr, pte_young(*pte)? "young":"");
                if(pte_young(*pte)){

                }
            }

        }
    up_write(&current->mm->mmap_sem);
} 


/*
    va -> pa translation
*/
static void find_page(unsigned long addr)
{
    printk(KERN_INFO"Virtual address:\t0x%08lx\n", addr);

    printk("Current PID: %d\n", current->pid);

    printk("PAGE_OFFSET = 0x%lx\n", PAGE_OFFSET);
    // printk("PHYS_OFFSET = 0x%lx\n", PHYS_OFFSET);
    printk("PGDIR_SHIFT = %d\n", PGDIR_SHIFT); 
    printk("P4D_SHIFT = %d\n",P4D_SHIFT); 
    printk("PUD_SHIFT = %d\n", PUD_SHIFT); 
    printk("PMD_SHIFT = %d\n", PMD_SHIFT); 
    printk("PAGE_SHIFT = %d\n", PAGE_SHIFT); 
    printk("PTRS_PER_PGD = %d\n", PTRS_PER_PGD);
    printk("PTRS_PER_P4D = %d\n", PTRS_PER_P4D);
    printk("PTRS_PER_PUD = %d\n", PTRS_PER_PUD);
    printk("PTRS_PER_PMD = %d\n", PTRS_PER_PMD);
    printk("PTRS_PER_PTE = %d\n", PTRS_PER_PTE);
    printk("PGDIR_MASK = 0x%lx\n", PGDIR_MASK);
    printk("P4D_MASK = 0x%lx\n", P4D_MASK);
    printk("PUD_MASK = 0x%lx\n", PUD_MASK);
    printk("PMD_MASK = 0x%lx\n", PMD_MASK);
    printk("PAGE_MASK = 0x%lx\n", PAGE_MASK);

    /*
        Structure of the 64-bit Virtual Memory Address:
        (With 5-level pagetable)
                 pgd_shift   p4d_shift   pud_shift   pmd_shift   page_shift
        [ pgd_index | p4d_index | pud_indux | pmd_index | page_index | page_offset ]
    */
    pgd_t* pgd; 
    p4d_t* p4d; 
    pud_t* pud; 
    pmd_t* pmd; 
    pte_t* pte; 
    

    if(!current->mm->pgd)
    {
        printk("invalid pgd entry!\n");
        return -1;
    }

    pgd = pgd_offset(current->mm, addr);
    if(pgd_none(*pgd))
    {
        printk("Wrong pgd\n");
        return- 1;
    }

    p4d = p4d_offset(pgd, addr);
    if(p4d_none(*p4d))
    {
        printk("Wrong p4d\n");
        return -1;
    }

    pud = pud_offset(p4d, addr);
    if(pud_none(*pud))
    {
        printk("Wrong pud\n");
        return-1;
    }

    pmd = pmd_offset(pud, addr);
    if(pmd_none(*pmd))
    {
        printk("Wrong pmd\n");
        return-1;
    }

    pte = pte_offset_kernel(pmd, addr);
    if(pte_none(*pte))
    {
        printk("Wrong pte\n");
        return-1;
    }

    printk("current->mm->pgd = 0x%08lx\n", current->mm->pgd);
    printk("pgd = 0x%08lx\n", pgd);
    printk("p4d = 0x%08lx\n", p4d);
    printk("pud = 0x%08lx\n", pud);
    printk("pmd = 0x%08lx\n", pmd);
    printk("pte = 0x%08lx\n", pte);

    
    /*
        physical address = [page frame address | page offset]
            where
            page frame address = pte_val(*pte) & PAGE_MASK
                and
                page offset = addr & ~ PAGE_MASK
    */
    unsigned long phy_addr = (pte_val(*pte) & PAGE_MASK) | (addr & ~PAGE_MASK);

    printk(KERN_INFO"Virtual address: \t0x%08lx\n", addr);
    printk(KERN_INFO"Physical address:\t0x%08lx\n", phy_addr);
}

/*
    Write val to the specified address
*/
static void write_val(unsigned long addr, unsigned long val)
{
    printk(KERN_INFO
        "Virtual address:\t0x%08lx\nValue to be written:\t0x%08lx", 
        addr, val);

    unsigned long* phy_addr;
    pte_t* pte = get_pte_by_vm(addr);
    struct page* page;
    
    if(pte == -1)
    {
        printk("Wrong virtual address!\n");
        return;
    }
    
    if(pte_none(*pte))
    {
        printk("Wrong pte\n");
        return-1;
    }
    printk(" pte_val(*pte): 0x%08lx\n", pte_val(*pte));
    phy_addr = (pte_val(*pte) & PAGE_MASK) | (addr & ~PAGE_MASK);
    printk(KERN_INFO"Physical address is:\t0x%08lx\n", phy_addr);

    if(pte_write(*pte))
    {
        printk("Address is writable\n");
        
        // printk("Previous content is: \t0x%08lx\n", (*phy_addr));
        // (*phy_addr) = val;

        page = pte_page(*pte);

        /* 
            Build a temporary map 
            from the virtual address to the physical page.
            Now we can access this page through the porinter vaddr.
        */
        void *vaddr = kmap(page);
        ((unsigned long*)vaddr)[addr & ~PAGE_MASK] = val;
        printk("Test: value  0x%08lx is written\n", 
            ((unsigned long*)vaddr)[addr & ~PAGE_MASK]);

        /* 
            Unmap this page. 
        */
        kunmap(vaddr);

        printk("Value is written to target physical address\n");
    }
    else
    {
        printk("Address is not writable\n");
    }

}

/*******************************************************************/

/*
    Using cat /proc/*filename to open the (virtual) file   
*/
static int proc_show(struct seq_file *m, void *v) {
    seq_printf(m, "YZT's proc\n");
    return 0;
}

static int proc_open(struct inode *inode, struct file *file) {
    return single_open(file, proc_show, NULL);
}


static ssize_t proc_write(struct file *file, const char __user *buffer, 
                            size_t count, loff_t *f_pos) 
{
    int i, mod = -1;
    char* para;
    char* content = kzalloc((count+1), GFP_KERNEL);
    unsigned long addr, val;
    pid_t pid;

    if(!content) return -ENOMEM;
    if(copy_from_user(content, buffer, count)){
        kfree(content);
        return EFAULT;
    }

    i = 0;
    while( (para = strsep(&content, " ")) != NULL )
    {
        if(i>1){
            printk("Wrong parameter!\n");
        }
        printk(KERN_INFO"%d: %s\n",i ,found);

        if (kstrtol(found, 10, &pid) != 0)
        {
            printk("Error translating address to int!\n");
        }

        i++;

    }
    
    list_vma();

    return count;
}


static const struct file_operations mkfile_fops = {
    // .owner= THIS_MODULE,
    .open = proc_open,          // the function called after opening operation
    .read = seq_read,
    .write = proc_write,        // the function called after writing operation
    // .llseek = seq_lseek,
    // .release = single_release
};

static char* dir_name;
static char* file_name = "PageAccessInfo";
struct proc_dir_entry *my_dir;
struct proc_dir_entry *my_file;

static int __init init_fun(void)
{
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
