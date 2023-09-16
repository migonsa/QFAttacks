import java.util.Random;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.*;

import filters.HashFunctions;
import filters.LFSR;
import filters.QuotientFilter;
import filters.QuotientFilterSec;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
 
import java.lang.management.ThreadMXBean;
import java.lang.management.ManagementFactory;


public class QFAttacks
{
    static Random rnd;
    static ThreadMXBean threadMXBean;
    static long threadId;


    static void init()
    {
        rnd = new Random();
        threadMXBean = ManagementFactory.getThreadMXBean();
        threadId = Thread.currentThread().getId();
    }

    static long start_time()
    {
        return threadMXBean.getThreadCpuTime(threadId);
    }

    static long start_time(long id)
    {
        return threadMXBean.getThreadCpuTime(id);
    }

    static long elapsed_time(long start)
    {
        return threadMXBean.getThreadCpuTime(threadId) - start;
    }

    static long elapsed_time(long id, long start)
    {
        return threadMXBean.getThreadCpuTime(id) - start;
    }
    
    static long get_random_input()
    {
        return rnd.nextLong();
    }

    static void write_csv(String csv_filename, List<String[]> csv_data)
    {
        write_csv(csv_filename, csv_data, false);
    }

    static void write_csv(String csv_filename, List<String[]> csv_data, boolean append)
    {
        try
        {
            File csvFile = new File(csv_filename);
            FileWriter fileWriter = new FileWriter(csvFile, append);
        
            for (String[] data : csv_data) {
                StringBuilder line = new StringBuilder();
                for (int i = 0; i < data.length; i++) {
                    line.append("\"");
                    line.append(data[i].replaceAll("\"","\"\""));
                    line.append("\"");
                    if (i != data.length - 1) {
                        line.append(',');
                    }
                }
                line.append("\n");
                fileWriter.write(line.toString());
            }
            fileWriter.close();
        }
        catch(IOException e)
        {
            e.printStackTrace();
            System.exit(1);
        }
    }

    static long get_index_input(int index, int power_of_two, int fbits, long shifts)
    {
        LFSR lfsr = new LFSR(fbits+power_of_two);
        int mask = (1 << power_of_two) - 1;
        long input;
        long hash;
        while(true)
        {
            input = rnd.nextLong();
            hash = lfsr.next(HashFunctions.xxhash(input), shifts);
            if ((((int)(hash)) & mask) == index)
            {
                return input;
            }
        }
    }

    static long[] gen_slot_array(int size, int power_of_two)
    {
        long[] slot_array = new long[size];
        int slot_mask = (1 << power_of_two) - 1;
        int cnt = 0;
        long rnd_slot_entry;
        int rnd_slot_index;

        while(cnt < size)
        {
            rnd_slot_entry = rnd.nextLong();
            rnd_slot_index = ((int)HashFunctions.xxhash(rnd_slot_entry)) & slot_mask;
            if (rnd_slot_index < size && slot_array[rnd_slot_index] == 0)
            {
                slot_array[rnd_slot_index] = rnd_slot_entry;
                cnt++;
            }
        }
        return slot_array;
    }

    static void insert_filter(QuotientFilter filter, int num_insertions, long[] insertions_array)
    {
        filter.insert(insertions_array[0], false);
        for(int i=0; i<num_insertions-1; i++)
        { 
            filter.insert(insertions_array[i], false);
        }
    }

    static void insert_filter(QuotientFilterSec filter, int num_insertions, long[] insertions_array)
    {
        filter.insert(insertions_array[0], false);
        for(int i=0; i<num_insertions-1; i++)
        { 
            filter.insert(insertions_array[i], false);
        }
    }

    static void insert_filter(QuotientFilter filter, int num_insertions, long seed, boolean sameInsertion)
    {
        rnd.setSeed(seed);
        long input = get_random_input();
        for(int i=0; i<num_insertions; i++)
        {
            if(!sameInsertion)
            {
                while(!filter.insert(get_random_input(), false));
            }
            else
            {
                while(!filter.insert(input, false))
                {
                    input = get_random_input();
                };
            }
            
        }
    }

    static void insert_filter(QuotientFilterSec filter, int num_insertions, long seed, boolean sameInsertion)
    {
        rnd.setSeed(seed);
        long input = get_random_input();
        for(int i=0; i<num_insertions; i++)
        {
            if(!sameInsertion)
            {
                while(!filter.insert(get_random_input(), false));
            }
            else
            {
                while(!filter.insert(input, false))
                {
                    input = get_random_input();
                };
            }
            
        }
    }
    
    static long measure_queries_time_multithread(QuotientFilter filter, int num_queries, long seed, long id)
    {
        rnd.setSeed(seed);
        long[] inputs = new long[num_queries];
        for(int i=0; i<num_queries; i++)
        {
            inputs[i] = get_random_input();
        }
        long time = start_time(id);
        for(int i=0; i<num_queries; i++)
        {
            filter.search(inputs[i]);
        }
        long elapsed = elapsed_time(id, time);
        return elapsed;
    }

    static long measure_queries_time_multithread(QuotientFilterSec filter, int num_queries, long seed, long id)
    {
        rnd.setSeed(seed);
        long[] inputs = new long[num_queries];
        for(int i=0; i<num_queries; i++)
        {
            inputs[i] = get_random_input();
        }
        long time = start_time(id);
        for(int i=0; i<num_queries; i++)
        {
            filter.search(inputs[i]);
        }
        long elapsed = elapsed_time(id, time);
        return elapsed;
    }



    static public void attack_insertion_failure_wb(int[] mbits, int fbits, boolean sameInsertion)
    {
        int m;
        long input, insertions;
		
        List<String[]> csv_data = new ArrayList<String[]>();
        String[] header = {"mbits", "num_insertions_until_insertion_failure"};
        csv_data.add(header);
        write_csv("attack_insertion_failure_wb.csv", csv_data);
        csv_data.clear();

        for(int i=0; i<mbits.length; i++)
        {
            m = mbits[i];
            insertions = 0;
            QuotientFilter qf = new QuotientFilter(m, fbits+3);
            input = get_index_input((1<<m)-1, m, fbits, 0);
            while(true)
            {
                insertions++;
                if (!qf.insert(input, false)) 
                    break;
                if(!sameInsertion)
                    input = get_index_input((1<<m)-1, m, fbits, 0);
            }
            String[] data = {""+m, ""+insertions};
            csv_data.add(data);
            write_csv("attack_insertion_failure_wb.csv", csv_data, true);
            csv_data.clear();
        }
    }


    static public void attack_insertion_failure_bb_multithread(int[] mbits, int fbits, int trials, boolean sameInsertion, 
                                                                int cores)
    { 
        long res[];
        long sum_insertions, sum_time, mean_insertions_until_failure;
        double mean_time_until_failure;

        List<String[]> csv_data = new ArrayList<String[]>();
        String[] header = {"mbits", "num_insertions_until_insertion_failure", "mean_time_until_failure"};
        csv_data.add(header);
        write_csv("attack_insertion_failure_bb.csv", csv_data);
        csv_data.clear();

        for(int i=0; i<mbits.length; i++)
        {
            sum_insertions = sum_time = 0;
            ExecutorService service = Executors.newWorkStealingPool(cores);
            final int m = mbits[i];
            Date date = new java.util.Date();
            System.out.format("%s : %d\n", date, m);
            Callable<long[]> task = ()->
            {
                Random rnd = new Random();
                long insertions = 0;
                QuotientFilter qf = new QuotientFilter(m, fbits+3);
                long id = Thread.currentThread().getId();
                long input = rnd.nextLong();
                long startTime = start_time(id);
                while(true)
                {
                    insertions++;
                    if (!qf.insert(input, false))
                        break;
                    if(!sameInsertion)
                        input = rnd.nextLong();
                }
                long elapsedTime = elapsed_time(id, startTime);
                return new long[]{insertions, elapsedTime};
            };
            List<Future<long[]>> results = new ArrayList<Future<long[]>>(trials);
            for (int t = 0; t<trials; t++)
            {
                results.add(service.submit(task));
            }
            for (int t = 0; t<trials; t++)
            {
                try
                {
                    res = results.get(t).get();
                    sum_insertions += res[0];
                    sum_time += res[1];
                } catch (Exception e) 
                {
                    e.printStackTrace();
                    System.exit(1);
                }
            }
            mean_insertions_until_failure = (long)(((double)sum_insertions)/trials);
            mean_time_until_failure = ((double)sum_time)/trials;
            String[] data = {""+m, ""+mean_insertions_until_failure, ""+mean_time_until_failure};
            csv_data.add(data);
            write_csv("attack_insertion_failure_bb.csv", csv_data, true);
            csv_data.clear();
        }
    }


    static public void attack_speed_degradation_wb_multithread(int[] mbits, int fbits, double[] control, 
                                double[] occupancy, int num_queries_min, int trials, int cores)
    {
        double o, c, mean_time;
        long sum_time;
        double[][] query_times = new double[occupancy.length][control.length];

        List<String[]> csv_data = new ArrayList<String[]>();
        String[] header = {"mbits", "o=80%|c=10%", "o=80%|c=5%", "o=80%|c=1%", "o=80%|c=0%",
                                    "o=60%|c=10%", "o=60%|c=5%", "o=60%|c=1%", "o=60%|c=0%",
                                    "o=40%|c=10%", "o=40%|c=5%", "o=40%|c=1%", "o=40%|c=0%",
                                    "o=20%|c=10%", "o=20%|c=5%", "o=20%|c=1%", "o=20%|c=0%",};
        csv_data.add(header);
        String filename = "attack_speed_degradation_wb.csv";
        write_csv(filename, csv_data);
        csv_data.clear();

        long[] slot_array = gen_slot_array((int)((1<<mbits[mbits.length-1])*control[0]), mbits[mbits.length-1]);

        for(int i=0; i<mbits.length; i++)
        {
            int m = mbits[i];
            int num_queries =  (int) Math.max(num_queries_min, Math.ceil((1<<m)*10));
            for(int j=0; j<occupancy.length; j++)
            {
                o = occupancy[j];
                long seed = get_random_input();
                for(int k=0; k<control.length; k++)
                {
                    c = control[k];
                    int num_insertions_legit = (int)((1<<m)*(o-c));
                    int num_insertions_attack = (int)((1<<m)*c);

                    Date date = new java.util.Date();
                    System.out.format("%s : %d - %f%% - %f%%\n", date, m, o, c);

                    sum_time = 0;

                    ExecutorService service = Executors.newWorkStealingPool(cores);
                    List<Future<Long>> results = new ArrayList<Future<Long>>(trials);
                    for (int t = 0; t<trials; t++)
                    {
                        int ft = t;
                        results.add(service.submit(new Callable<Long>()
                        {
                            public Long call()
                            {
                                long id = Thread.currentThread().getId();
                                QuotientFilter qf = new QuotientFilter(m, fbits+3);
                                insert_filter(qf, num_insertions_legit, seed+ft, false);
                                if(num_insertions_attack != 0)
                                {
                                    insert_filter(qf, num_insertions_attack, slot_array);
                                }
                                return measure_queries_time_multithread(qf, num_queries, seed+ft+2, id);
                            }
                        }));
                    }
                    for(int t=0; t<trials; t++)
                    {
                        try
                        {
                            long result = results.get(t).get();
                            sum_time += result;
                        } catch (Exception e) 
                        {
                            System.exit(1);
                        }
                    }
                    mean_time = ((double)sum_time)/trials/num_queries;
                    query_times[j][k] = mean_time;
                }
            }
            List<String> row = new ArrayList<String>();
            row.add(""+m);
            for (int j=0; j<occupancy.length; j++)
            {
                for (int k=0; k<control.length; k++)
                {
                    row.add(""+query_times[j][k]);
                }
            }
            String[] data = row.toArray(new String[0]);
            csv_data.add(data);
            write_csv(filename, csv_data, true);
            csv_data.clear();
        }
    }


    static public void attack_speed_degradation_bb_multithread(int[] mbits, int fbits, double[] control, 
                        double[] occupancy, int num_queries_min, int trials, boolean sameInsertion, int cores)
    {
        double o, c, mean_time;
        long sum_time;
        double[][] query_times = new double[occupancy.length][control.length];

        List<String[]> csv_data = new ArrayList<String[]>();
        String[] header = {"mbits", "o=80%|c=10%", "o=80%|c=5%", "o=80%|c=1%", "o=80%|c=0%",
                                    "o=60%|c=10%", "o=60%|c=5%", "o=60%|c=1%", "o=60%|c=0%",
                                    "o=40%|c=10%", "o=40%|c=5%", "o=40%|c=1%", "o=40%|c=0%",
                                    "o=20%|c=10%", "o=20%|c=5%", "o=20%|c=1%", "o=20%|c=0%",};
        csv_data.add(header);
        String filename =  "attack_speed_degradation_bb.csv";
        write_csv(filename, csv_data);
        csv_data.clear();

        for(int i=0; i<mbits.length; i++)
        {
            int m = mbits[i];
            int num_queries =  (int) Math.max(num_queries_min, Math.ceil((1<<m)*10));
            for(int j=0; j<occupancy.length; j++)
            {
                o = occupancy[j];
                long seed = get_random_input();
                for(int k=0; k<control.length; k++)
                {
                    c = control[k];
                    int num_insertions_legit = (int)((1<<m)*(o-c));
                    int num_insertions_attack = (int)((1<<m)*c);

                    Date date = new java.util.Date();
                    System.out.format("%s : %d - %f%% - %f%%\n", date, m, o, c);

                    sum_time = 0;

                    ExecutorService service = Executors.newWorkStealingPool(cores);
                    List<Future<Long>> results = new ArrayList<Future<Long>>(trials);
                    for (int t = 0; t<trials; t++)
                    {
                        int ft = t;
                        results.add(service.submit(new Callable<Long>()
                        {
                            public Long call()
                            {
                                long id = Thread.currentThread().getId();
                                QuotientFilter qf = new QuotientFilter(m, fbits+3);
                                insert_filter(qf, num_insertions_legit, seed+ft, false);
                                if(num_insertions_attack != 0)
                                {
                                    insert_filter(qf, num_insertions_attack, seed+ft+1, sameInsertion);
                                }
                                return measure_queries_time_multithread(qf, num_queries, seed+ft+2, id);
                            }
                        }));
                    }
                    for(int t=0; t<trials; t++)
                    {
                        try
                        {
                            long result = results.get(t).get();
                            sum_time += result;
                        } catch (Exception e) 
                        {
                            System.exit(1);
                        }
                    }
                    mean_time = ((double)sum_time)/trials/num_queries;
                    query_times[j][k] = mean_time;
                }
            }
            List<String> row = new ArrayList<String>();
            row.add(""+m);
            for (int j=0; j<occupancy.length; j++)
            {
                for (int k=0; k<control.length; k++)
                {
                    row.add(""+query_times[j][k]);
                }
            }
            String[] data = row.toArray(new String[0]);
            csv_data.add(data);
            write_csv(filename, csv_data, true);
            csv_data.clear();
        }
    }

//-----------------------------------------------------SECURITY ATTACKS------------------------------------------------------------------------------------------------------------


    static public void attack_insertion_failure_wb_sec(int[] mbits, int fbits, boolean sameInsertion)
    {
        int m;
        long input, insertions;
		
        List<String[]> csv_data = new ArrayList<String[]>();
        String[] header = {"mbits", "num_insertions_until_insertion_failure"};
        csv_data.add(header);
        String filename = "attack_insertion_failure_wb_sec.csv";
        write_csv(filename, csv_data);
        csv_data.clear();

        for(int i=0; i<mbits.length; i++)
        {
            m = mbits[i];
            insertions = 0;
            QuotientFilterSec qf = new QuotientFilterSec(m, fbits+3);
            input = get_index_input((1<<m)-1, m, fbits, qf.shifts);
            while(qf.num_inserted_fp < ((1L<<m)))
            {
                insertions++;
                if (!qf.insert(input, false)) 
                    break;
                if(!sameInsertion)
                    input = get_index_input((1<<m)-1, m, fbits, qf.shifts);
            }
            String[] data = {""+m, ""+insertions, ""+qf.shifts/4};
            csv_data.add(data);
            write_csv(filename, csv_data, true);
            csv_data.clear();
        }
    }


    static public void attack_insertion_failure_wb_sec_multithread(int[] mbits, int fbits, int trials, boolean sameInsertion, 
                                                                    int cores)
    { 
        long res[];
        long sum_insertions, sum_time, mean_insertions_until_failure, mean_reconstructions;
        double mean_time_until_failure;

        List<String[]> csv_data = new ArrayList<String[]>();
        String[] header = {"mbits", "num_insertions_until_insertion_failure", "mean_time_until_failure", "mean_reconstructions"};
        csv_data.add(header);
        String filename = "attack_insertion_failure_wb_sec.csv";
        write_csv(filename, csv_data);
        csv_data.clear();

        for(int i=0; i<mbits.length; i++)
        {
            sum_insertions = sum_time = mean_reconstructions = 0;
            ExecutorService service = Executors.newWorkStealingPool(cores);
            final int m = mbits[i];
            Date date = new java.util.Date();
            System.out.format("%s : %d\n", date, m);
            Callable<long[]> task = ()->
            {
                long insertions = 0;
                QuotientFilterSec qf = new QuotientFilterSec(m, fbits+3);
                long id = Thread.currentThread().getId();
                long input = get_index_input((1<<m)-1, m, fbits, qf.shifts);
                long startTime = start_time(id);
                while(qf.num_inserted_fp <= qf.get_logical_num_slots_plus_extensions() 
                        && (qf.shifts/qf.reconstruction_shifts) < 10)
                {
                    insertions++;
                    if (!qf.insert(input, false)) 
                        break;
                    if(!sameInsertion)
                        input = get_index_input((1<<m)-1, m, fbits, qf.shifts);
                }
                long elapsedTime = elapsed_time(id, startTime);
                return new long[]{insertions, elapsedTime, qf.shifts/qf.reconstruction_shifts};
            };
            List<Future<long[]>> results = new ArrayList<Future<long[]>>(trials);
            for (int t = 0; t<trials; t++)
            {
                results.add(service.submit(task));
            }
            for (int t = 0; t<trials; t++)
            {
                try
                {
                    res = results.get(t).get();
                    sum_insertions += res[0];
                    sum_time += res[1];
                    mean_reconstructions += res[2];
                } catch (Exception e) 
                {
                    e.printStackTrace();
                    System.exit(1);
                }
            }
            mean_insertions_until_failure = (long)(((double)sum_insertions)/trials);
            mean_time_until_failure = ((double)sum_time)/trials;
            mean_reconstructions /= trials;
            String[] data = {""+m, ""+mean_insertions_until_failure, ""+mean_time_until_failure, ""+mean_reconstructions};
            csv_data.add(data);
            write_csv(filename, csv_data, true);
            csv_data.clear();
        }
    }


    static public void attack_insertion_failure_bb_sec_multithread(int[] mbits, int fbits, int trials, boolean sameInsertion, 
                                                                    int cores)
    { 
        long res[];
        long sum_insertions, sum_time, mean_insertions_until_failure, mean_reconstructions;
        double mean_time_until_failure;

        List<String[]> csv_data = new ArrayList<String[]>();
        String[] header = {"mbits", "num_insertions_until_insertion_failure", "mean_time_until_failure", "mean_reconstructions"};
        csv_data.add(header);
        String filename = "attack_insertion_failure_bb_sec.csv";
        write_csv(filename, csv_data);
        csv_data.clear();

        for(int i=0; i<mbits.length; i++)
        {
            sum_insertions = sum_time = mean_reconstructions = 0;
            ExecutorService service = Executors.newWorkStealingPool(cores);
            final int m = mbits[i];
            Date date = new java.util.Date();
            System.out.format("%s : %d\n", date, m);
            Callable<long[]> task = ()->
            {
                Random rnd = new Random();
                long insertions = 0;
                QuotientFilterSec qf = new QuotientFilterSec(m, fbits+3);
                long id = Thread.currentThread().getId();
                long input = rnd.nextLong();
                long startTime = start_time(id);
                while(qf.num_inserted_fp < qf.get_logical_num_slots_plus_extensions()*10)
                {
                    insertions++;
                    if (!qf.insert(input, false))
                        break;
                    if(!sameInsertion)
                        input = rnd.nextLong();
                }
                long elapsedTime = elapsed_time(id, startTime);
                return new long[]{insertions, elapsedTime, qf.shifts/qf.reconstruction_shifts};
            };
            List<Future<long[]>> results = new ArrayList<Future<long[]>>(trials);
            for (int t = 0; t<trials; t++)
            {
                results.add(service.submit(task));
            }
            for (int t = 0; t<trials; t++)
            {
                try
                {
                    res = results.get(t).get();
                    sum_insertions += res[0];
                    sum_time += res[1];
                    mean_reconstructions += res[2];
                } catch (Exception e) 
                {
                    e.printStackTrace();
                    System.exit(1);
                }
            }
            mean_insertions_until_failure = (long)(((double)sum_insertions)/trials);
            mean_time_until_failure = ((double)sum_time)/trials;
            mean_reconstructions /= trials;
            String[] data = {""+m, ""+mean_insertions_until_failure, ""+mean_time_until_failure, ""+mean_reconstructions};
            csv_data.add(data);
            write_csv(filename, csv_data, true);
            csv_data.clear();
        }
    }


    static public void attack_speed_degradation_wb_sec_multithread(int[] mbits, int fbits, double[] control, 
                                double[] occupancy, int num_queries_min, int trials, int cores)
    {
        double o, c, mean_time;
        long sum_time;
        double[][] query_times = new double[occupancy.length][control.length];

        List<String[]> csv_data = new ArrayList<String[]>();
        String[] header = {"mbits", "o=80%|c=10%", "o=80%|c=5%", "o=80%|c=1%", "o=80%|c=0%",
                                    "o=60%|c=10%", "o=60%|c=5%", "o=60%|c=1%", "o=60%|c=0%",
                                    "o=40%|c=10%", "o=40%|c=5%", "o=40%|c=1%", "o=40%|c=0%",
                                    "o=20%|c=10%", "o=20%|c=5%", "o=20%|c=1%", "o=20%|c=0%",};
        csv_data.add(header);
        String filename = "attack_speed_degradation_wb_sec.csv";
        write_csv(filename, csv_data);
        csv_data.clear();

        long[] slot_array = gen_slot_array((int)((1<<mbits[mbits.length-1])*control[0]), mbits[mbits.length-1]);

        for(int i=0; i<mbits.length; i++)
        {
            int m = mbits[i];
            int num_queries =  (int) Math.max(num_queries_min, Math.ceil((1<<m)*10));
            for(int j=0; j<occupancy.length; j++)
            {
                o = occupancy[j];
                long seed = get_random_input();
                for(int k=0; k<control.length; k++)
                {
                    c = control[k];
                    int num_insertions_legit = (int)((1<<m)*(o-c));
                    int num_insertions_attack = (int)((1<<m)*c);

                    Date date = new java.util.Date();
                    System.out.format("%s : %d - %f%% - %f%%\n", date, m, o, c);

                    sum_time = 0;

                    ExecutorService service = Executors.newWorkStealingPool(cores);
                    List<Future<Long>> results = new ArrayList<Future<Long>>(trials);
                    for (int t = 0; t<trials; t++)
                    {
                        int ft = t;
                        results.add(service.submit(new Callable<Long>()
                        {
                            public Long call()
                            {
                                long id = Thread.currentThread().getId();
                                QuotientFilterSec qf = new QuotientFilterSec(m, fbits+3);
                                insert_filter(qf, num_insertions_legit, seed+ft, false);
                                if(num_insertions_attack != 0)
                                {
                                    insert_filter(qf, num_insertions_attack, slot_array);
                                }
                                while (qf.reconstruct(true) == null);
                                return measure_queries_time_multithread(qf, num_queries, seed+ft+2, id);
                            }
                        }));
                    }
                    for(int t=0; t<trials; t++)
                    {
                        try
                        {
                            long result = results.get(t).get();
                            sum_time += result;
                        } catch (Exception e) 
                        {
                            System.exit(1);
                        }
                    }
                    mean_time = ((double)sum_time)/trials/num_queries;
                    query_times[j][k] = mean_time;
                }
            }
            List<String> row = new ArrayList<String>();
            row.add(""+m);
            for (int j=0; j<occupancy.length; j++)
            {
                for (int k=0; k<control.length; k++)
                {
                    row.add(""+query_times[j][k]);
                }
            }
            String[] data = row.toArray(new String[0]);
            csv_data.add(data);
            write_csv(filename, csv_data, true);
            csv_data.clear();
        }
    }


    static public void attack_speed_degradation_bb_sec_multithread(int[] mbits, int fbits, double[] control, 
                        double[] occupancy, int num_queries_min, int trials, boolean sameInsertion, int cores)
    {
        double o, c, mean_time;
        long sum_time;
        double[][] query_times = new double[occupancy.length][control.length];

        List<String[]> csv_data = new ArrayList<String[]>();
        String[] header = {"mbits", "o=80%|c=10%", "o=80%|c=5%", "o=80%|c=1%", "o=80%|c=0%",
                                    "o=60%|c=10%", "o=60%|c=5%", "o=60%|c=1%", "o=60%|c=0%",
                                    "o=40%|c=10%", "o=40%|c=5%", "o=40%|c=1%", "o=40%|c=0%",
                                    "o=20%|c=10%", "o=20%|c=5%", "o=20%|c=1%", "o=20%|c=0%",};
        csv_data.add(header);
        String filename = "attack_speed_degradation_bb_sec.csv";
        write_csv(filename, csv_data);
        csv_data.clear();

        for(int i=0; i<mbits.length; i++)
        {
            int m = mbits[i];
            int num_queries =  (int) Math.max(num_queries_min, Math.ceil((1<<m)*10));
            for(int j=0; j<occupancy.length; j++)
            {
                o = occupancy[j];
                long seed = get_random_input();
                for(int k=0; k<control.length; k++)
                {
                    c = control[k];
                    int num_insertions_legit = (int)((1<<m)*(o-c));
                    int num_insertions_attack = (int)((1<<m)*c);

                    Date date = new java.util.Date();
                    System.out.format("%s : %d - %f%% - %f%%\n", date, m, o, c);

                    sum_time = 0;

                    ExecutorService service = Executors.newWorkStealingPool(cores);
                    List<Future<Long>> results = new ArrayList<Future<Long>>(trials);
                    for (int t = 0; t<trials; t++)
                    {
                        int ft = t;
                        results.add(service.submit(new Callable<Long>()
                        {
                            public Long call()
                            {
                                long id = Thread.currentThread().getId();
                                QuotientFilterSec qf = new QuotientFilterSec(m, fbits+3);
                                qf.auto_reconstruction = false;
                                insert_filter(qf, num_insertions_legit, seed+ft, false);
                                if(num_insertions_attack != 0)
                                {
                                    insert_filter(qf, num_insertions_attack, seed+ft+1, sameInsertion);
                                }
                                return measure_queries_time_multithread(qf, num_queries, seed+ft+2, id);
                            }
                        }));
                    }
                    for(int t=0; t<trials; t++)
                    {
                        try
                        {
                            long result = results.get(t).get();
                            sum_time += result;
                        } catch (Exception e) 
                        {
                            System.exit(1);
                        }
                    }
                    mean_time = ((double)sum_time)/trials/num_queries;
                    query_times[j][k] = mean_time;
                }
            }
            List<String> row = new ArrayList<String>();
            row.add(""+m);
            for (int j=0; j<occupancy.length; j++)
            {
                for (int k=0; k<control.length; k++)
                {
                    row.add(""+query_times[j][k]);
                }
            }
            String[] data = row.toArray(new String[0]);
            csv_data.add(data);
            write_csv(filename, csv_data, true);
            csv_data.clear();
        }
    }




    static public void main(String[] args) 
    {
        init();

        int[] mbits = {16, 17, 18, 19, 20};
        int fbits = 13;
        boolean sameInsertion = true;
        int trials = 1000;
        int cores = 20;
	
	attack_insertion_failure_wb(mbits, fbits, sameInsertion);
        attack_insertion_failure_bb_multithread(mbits, fbits, trials, sameInsertion, cores);
        attack_insertion_failure_bb_sec_multithread(mbits, fbits, trials, sameInsertion, cores);
        attack_insertion_failure_wb_sec_multithread(mbits, fbits, trials, false, cores); 

        double[] control = {0.1, 0.05, 0.01, 0.0};
        double[] occupancy = {0.8, 0.6, 0.4, 0.2};
        int num_queries_min = 100;

        attack_speed_degradation_wb_multithread(mbits, fbits, control, occupancy, num_queries_min, trials, cores);
        attack_speed_degradation_bb_multithread(mbits, fbits, control, occupancy, num_queries_min, trials, sameInsertion, cores);
        attack_speed_degradation_wb_sec_multithread(mbits, fbits, control, occupancy, num_queries_min, trials, cores);
        attack_speed_degradation_bb_sec_multithread(mbits, fbits, control, occupancy, num_queries_min, trials, sameInsertion, cores);
    }
}
