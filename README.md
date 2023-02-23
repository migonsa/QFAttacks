# QFAttacks

This repository contains the code necessary to perform the simulations of the paper ***On the Security of Quotient Filters: Attacks and Potential Countermeasures*** which is currently under review in IEEE Transactions on Computers.

These simulations are attacks on the security of the Quotient Filter whose implementation, used for both white box and black box, can be found in the following repository: [FilterLibrary](https://github.com/nivdayan/FilterLibrary).

## Compilation Intructions

The code can run on Java version 11 and above.
As the code in this repository requires the code base, please refer to the compilation instructions of the [FilterLibrary](https://github.com/nivdayan/FilterLibrary) repository first. Once compiled place the file *QFAttacks.java* outside the package named *filters*. Then compile as follows:

```sh
javac QFAttacks.java
```

## Running Instructions
To make sure that [FilterLibrary repository](https://github.com/nivdayan/FilterLibrary) has been compiled correctly, please refer to its running instructions beforehand, since they contain verification tests. Once this is done, execute the attacks as follows:

```sh
java QFAttacks
```

## Results
The results obtained from the execution of *QFAttacks* are the CSV format files used to draw the graphs of the paper. These are available in the current repository, although it should be noted that, since these are simulations, the numerical results may vary slightly from one run to another.  
A list of the results to be obtained with a brief description of each is shown below. For more information refer to the paper.
- **attack_insertion_failure_wb.csv**   &#8594;   It contains the numerical results of attacks intended to cause insertion failures in the filter when used as a white box.
- **attack_insertion_failure_bb.csv**   &#8594;   It contains the numerical results of attacks intended to cause insertion failures in the filter when used as a black box.
- **attack_speed_degradation_wb.csv**   &#8594;   It contains the numerical results of attacks intended to cause a degradation in the speed of filter queries when used as a white box.
- **attack_speed_degradation_bb.csv**   &#8594;   It contains the numerical results of attacks intended to cause a degradation in the speed of filter queries when used as a black box.

## License

MIT
