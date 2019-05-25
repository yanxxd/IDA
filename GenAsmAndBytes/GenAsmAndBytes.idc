//
//      Sample IDC program to automate IDA.
//
//      IDA can be run from the command line in the
//      batch (non-interactive) mode.
//
//      If IDA is started with
//
//              idag -A -Sanalysis.idc file
//
//      then this IDC file will be executed. It performs the following:
//
//        - the code segment is analyzed
//        - the output file is created
//        - IDA exits to OS
//
//      Feel free to modify this file as you wish
//      (or write your own script/plugin to automate IDA)
//
//      Since the script calls the Exit() function at the end,
//      it can be used in the batch files (use text mode idaw.exe)
//
//      NB: "idag -B file" is equivalent to the command line above
//

#include <idc.idc>

static main()
{
  // turn on coagulation of data in the final pass of analysis
  SetShortPrm(INF_AF2, GetShortPrm(INF_AF2) | AF2_DODATA);

  Message("Waiting for the end of the auto analysis...\n");
  Wait();
  Message("\n\n------ Creating the output file.... --------\n");
  
  //1. 生成asm文件
  Message("------ generate asm begin ------\n");
  auto file = GetIdbPath()[0:-4] + ".asm";
  auto fp = fopen(file, "w");  
  GenerateFile(OFILE_LST, fp, 0, BADADDR, 0);
  fclose(fp);
  Message("------ generate asm end ------\n");
  
  //2. 生成bytes文件
  Message("------ generate bytes begin ------\n");
  auto begin, end, addr, b, str;
  file = GetIdbPath()[0:-4] + ".bytes";
  fp = fopen(file, "w");
  begin = MinEA();
  end = MaxEA();//BADADDR;
  
  fprintf(fp, "%08X ", begin); 
  for ( addr = begin; addr < end; addr++ )
  {
	// string  ltoa            (long n,long radix);    // convert to ascii string
    // long    writestr        (long handle,string str);
    //fputc(Byte(addr), fp);
    if(0 == addr % 16)
    {
		if(addr - begin > 0)
	      fprintf(fp, "\n%08X ", addr); 
    }
	else
	{		
      writestr(fp, " ");
	}
	if( isLoaded(addr) )
	{
	  b = Byte(addr);
	  str = ltoa(b, 16);
	  if(b < 16)
	    writestr(fp, "0");
      writestr(fp, str);
	}
	else
	{
      writestr(fp, "??");
	}
  }
  fclose(fp);
  Message("------ generate bytes end ------\n");
  
  Message("------ All done, exiting... ------\n");
  SaveBase(0, 0)
  Exit(0);                              // exit to OS, error code 0 - success
}
