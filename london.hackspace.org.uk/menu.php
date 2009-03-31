<?php
function menulink($url, $name, $title) {
    global $page;
    $ret = '<li';
    if ($page == $name) {
        $ret .= ' class="active"';
    }   
    $ret .= '>';
    if ($page != $name) {
        $ret .= '<a href="' . $url . '">';
    }
    $ret .= $title;
    if ($page != $name) {
        $ret .= '</a>';
    }
    $ret .= '</li>';
    return $ret;
}

?>
<div class="yui-b">
    <ul id="menu">
        <?=menulink('/', 'about', 'About');?>
        <li><a href="http://wiki.hackspace.org.uk">Wiki</a></li>
        <li><a href="http://groups.google.com/group/london-hack-space">Mailing List</a></li>
        <?=menulink('/irc', 'irc', 'IRC');?>
        <?=menulink('/donate', 'donate', 'Donate');?>
        <?=menulink('/events', 'events', 'Events');?>
    </ul>
</div>