import worker from '../../backend/worker.mjs';
import frontend from '../../index.html';
export default {
 async fetch(request,env,ctx){
  if(new URL(request.url).pathname==='/app'){
   const html=frontend.replaceAll('https://edgeai-backend.frederico-fahndrich.workers.dev','http://localhost:5500')
    .replace('<head>','<head><base href="https://fredericofahndrich.github.io/EdgeAI/">')
    .replace('<title>EDGE AI</title>','<title>LOCAL AUTH TEST — EDGE AI</title>');
   return new Response(html,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});
  }
  return worker.fetch(request,env,ctx);
 }
};
