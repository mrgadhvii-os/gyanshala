// Main JavaScript file for GyanShala

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips if Bootstrap is available
    if (typeof bootstrap !== 'undefined') {
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }

    // Prevent content downloading
    document.addEventListener('contextmenu', function(e) {
        if (e.target.tagName === 'VIDEO' || e.target.tagName === 'IMG') {
            e.preventDefault();
        }
    });

    // Add smooth scrolling for in-page navigation
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // Add animation to elements as they become visible
    const animateOnScroll = function() {
        const elements = document.querySelectorAll('.animate-on-scroll');
        
        elements.forEach(element => {
            const elementPosition = element.getBoundingClientRect().top;
            const windowHeight = window.innerHeight;
            
            if (elementPosition < windowHeight - 50) {
                element.classList.add('animated');
            }
        });
    };

    // Run on initial load
    animateOnScroll();
    
    // Run on scroll
    window.addEventListener('scroll', animateOnScroll);
    
    // Security measures for video content
    const createSecureEnvironment = function() {
        // Block developer tools shortcut keys
        document.addEventListener('keydown', function(e) {
            // Prevent F12 key
            if (e.key === 'F12' || e.keyCode === 123) {
                e.preventDefault();
                return false;
            }
            
            // Prevent Ctrl+Shift+I (Chrome dev tools)
            if (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.keyCode === 73)) {
                e.preventDefault();
                return false;
            }
            
            // Prevent Ctrl+Shift+J (Chrome dev tools)
            if (e.ctrlKey && e.shiftKey && (e.key === 'J' || e.key === 'j' || e.keyCode === 74)) {
                e.preventDefault();
                return false;
            }
            
            // Prevent Ctrl+Shift+C (Chrome dev tools inspect)
            if (e.ctrlKey && e.shiftKey && (e.key === 'C' || e.key === 'c' || e.keyCode === 67)) {
                e.preventDefault();
                return false;
            }
        });
    };
    
    // Apply security measures for all pages
    createSecureEnvironment();
}); 