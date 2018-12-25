# ClassInformerForMacho
I have used the ClassInformer C++ plugin in IDA, and it is wonderful.
But it doesn't support gnu compiler, useless for Apple's mach-o file.
So I just create the IDAPython to make it.
Now, it can:
1. Scan all the virtual functions in the segment you specified, default is '__const'. In this step, those unknown vtbl can be recognized.
2. Add new 'ClassNameVtbl' type to Local types window, so you can use it conveniently when reversing.
