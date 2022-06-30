const demoBtn = document.querySelector("#demo");
const formin = document.querySelector(".demo1");
const forminput = document.querySelector(".demo2");
const demoform = document.querySelector("#formDemo");


demoBtn.addEventListener("click", e => {
    forminput.value = "demo";
    formin.value = "demo";
    demoform.submit();
    console.log("hi");
});